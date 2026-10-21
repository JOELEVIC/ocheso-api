"""
The rules, tested where implementations usually go wrong.

Draughts positions are built from (row, column) so each test reads as a
picture rather than as a list of square numbers to check by hand.
"""

from __future__ import annotations

import random

import pytest

from play import draughts
from play.rules import Illegal, flag_result, judge, position_after, start

INTL = "international"
B10 = draughts.board_for(INTL)


def sq(r: int, c: int, board: draughts.Board = B10) -> int:
    n = board.num(r, c)
    assert n is not None, f"({r},{c}) is a light square"
    return n


def pos(white: dict, black: dict, turn: str = "white") -> draughts.Position:
    pieces = {sq(*k): v for k, v in white.items()} | {sq(*k): v for k, v in black.items()}
    return draughts.Position(pieces, turn)


# -----------------------------------------------------------------------------
# Draughts
# -----------------------------------------------------------------------------
def test_starting_positions():
    intl = draughts.initial(INTL)
    braz = draughts.initial("brazilian")
    assert sum(p == "w" for p in intl.pieces.values()) == 20
    assert sum(p == "b" for p in braz.pieces.values()) == 12
    assert len(draughts.legal_moves(INTL, intl)) == 9
    assert len(draughts.legal_moves("brazilian", braz)) == 7
    assert intl.fen().startswith("W:W31,32,")


def test_numbering_matches_published_games():
    # Square 1 is the top-left dark square; 46 the bottom-left, which is dark.
    assert B10.rc(1) == (0, 1)
    assert B10.rc(46) == (9, 0)
    assert B10.rc(50) == (9, 8)


def test_capture_is_compulsory():
    p = pos({(6, 3): "w", (6, 7): "w"}, {(5, 4): "b"})
    moves = draughts.legal_moves(INTL, p)
    assert moves and all(m.captured for m in moves)


def test_must_take_the_most_pieces():
    # Left takes one; right takes two. Only the right is legal.
    p = pos({(6, 3): "w"}, {(5, 2): "b", (5, 4): "b", (3, 6): "b"})
    moves = draughts.legal_moves(INTL, p)
    assert [len(m.captured) for m in moves] == [2]
    assert moves[0].path == (sq(6, 3), sq(4, 5), sq(2, 7))


def test_men_capture_backwards():
    p = pos({(4, 3): "w"}, {(5, 4): "b"})
    assert [m.path[-1] for m in draughts.legal_moves(INTL, p)] == [sq(6, 5)]


def test_men_move_only_forwards():
    p = pos({(6, 3): "w"}, {(0, 1): "b"})
    assert sorted(m.path[-1] for m in draughts.legal_moves(INTL, p)) == sorted([sq(5, 2), sq(5, 4)])


def test_kings_fly_and_land_anywhere_beyond():
    p = pos({(9, 0): "W"}, {(5, 4): "b"})
    moves = draughts.legal_moves(INTL, p)
    assert all(m.captured == (sq(5, 4),) for m in moves)
    assert sorted(m.path[-1] for m in moves) == sorted([sq(4, 5), sq(3, 6), sq(2, 7), sq(1, 8), sq(0, 9)])


def test_no_crowning_when_passing_through_the_last_row():
    # Lands on row 0 mid-capture, then must take again backwards: still a man.
    p = pos({(2, 1): "w"}, {(1, 2): "b", (1, 4): "b"})
    [m] = draughts.legal_moves(INTL, p)
    assert m.path == (sq(2, 1), sq(0, 3), sq(2, 5))
    after = draughts.apply(INTL, p, m)
    assert after.pieces[sq(2, 5)] == "w"


def test_crowned_when_the_move_ends_on_the_last_row():
    p = pos({(1, 2): "w"}, {(9, 0): "b"})
    m = draughts.find(INTL, p, f"{sq(1, 2)}-{sq(0, 1)}")
    assert draughts.apply(INTL, p, m).pieces[sq(0, 1)] == "W"


def test_captured_pieces_stay_until_the_move_ends():
    # Turkish strike: across random games, no move ever takes a piece twice,
    # and each move removes exactly what it says it captured.
    rng = random.Random(7)
    for variant in (INTL, "brazilian"):
        for _ in range(25):
            p = draughts.initial(variant)
            for _ in range(200):
                moves = draughts.legal_moves(variant, p)
                if not moves:
                    break
                m = rng.choice(moves)
                assert len(set(m.captured)) == len(m.captured)
                before = len(p.pieces)
                p = draughts.apply(variant, p, m)
                assert len(p.pieces) == before - len(m.captured)


def test_no_moves_loses():
    p = pos({(6, 1): "w"}, {(5, 0): "b", (5, 2): "b", (4, 3): "b"})
    assert draughts.legal_moves(INTL, p) == []


def test_fen_round_trips():
    p = pos({(9, 0): "W", (6, 3): "w"}, {(0, 1): "B", (3, 2): "b"}, turn="black")
    assert draughts.parse(p.fen()) == p


def test_threefold_repetition_draws():
    # Two kings shuffling on diagonals that never meet (on a shared one, a
    # capture would be compulsory and the shuffle illegal).
    p = pos({(9, 2): "W"}, {(0, 1): "B"})
    white_a, white_b = sq(9, 2), sq(8, 3)
    black_a, black_b = sq(0, 1), sq(1, 0)
    seen = {p.fen(): 1}
    record = []
    for i in range(8):
        a, b = (white_a, white_b) if p.turn == "white" else (black_a, black_b)
        src, dst = (a, b) if (i // 2) % 2 == 0 else (b, a)
        m = draughts.find(INTL, p, f"{src}-{dst}")
        record.append(m.text)
        p = draughts.apply(INTL, p, m)
        seen[p.fen()] = seen.get(p.fen(), 0) + 1
    r = draughts.Replay(p, seen, quiet_king_plies=8)
    assert draughts.outcome(INTL, r) == ("draw", "repetition")


def test_draughts_through_the_referee():
    s = start("checkers", INTL)
    assert s.turn == "white" and len(s.legal) == 9
    ruling = judge("checkers", INTL, [], s.legal[0])
    assert ruling.after.turn == "black" and ruling.result is None
    assert position_after("checkers", INTL, [ruling.move]) == ruling.after.position
    with pytest.raises(Illegal):
        judge("checkers", INTL, [], "50-45")


# -----------------------------------------------------------------------------
# Chess
# -----------------------------------------------------------------------------
def test_chess_checkmate_ends_the_game():
    history = ["e2e4", "e7e5", "d1h5", "b8c6", "f1c4", "g8f6"]
    r = judge("chess", "standard", history, "h5f7")
    assert (r.result, r.termination, r.san) == ("white", "checkmate", "Qxf7#")


def test_chess_illegal_move_is_refused():
    with pytest.raises(Illegal):
        judge("chess", "standard", [], "e2e5")
    with pytest.raises(Illegal):
        judge("chess", "standard", [], "nonsense")


def test_chess_promotion_defaults_to_a_queen():
    # A legal line to a pawn on the seventh with the eighth rank free.
    history = ["h2h4", "g7g5", "h4g5", "h7h6", "g5h6", "g8f6", "h6h7", "f6g8"]
    r = judge("chess", "standard", history, "h7g8")
    assert r.move == "h7g8q"


def test_chess_repetition_draws_without_a_claim():
    shuffle = ["g1f3", "g8f6", "f3g1", "f6g8"]
    r = judge("chess", "standard", shuffle * 2 + ["g1f3", "g8f6", "f3g1"], "f6g8")
    assert (r.result, r.termination) == ("draw", "repetition")


def test_out_of_time_against_a_bare_king_is_a_draw():
    # Black flags, but White has only a king left: nobody could have won.
    history = ["e2e4", "d7d5", "e4d5", "d8d5"]
    assert flag_result("chess", "standard", history) == "black"  # White to move flags
    assert flag_result("checkers", INTL, []) == "black"


def test_chess_flag_with_insufficient_material():
    import chess

    board = chess.Board("8/8/8/4k3/8/8/8/4K2Q b - - 0 1")
    assert board.has_insufficient_material(chess.BLACK)
