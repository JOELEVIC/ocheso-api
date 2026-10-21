"""
One interface over both games, for the referee.

Every ruling is made from the game's whole record, not from the last position:
repetition draws need the history, and rebuilding from the moves means a
corrupted stored position is caught (it would not match) rather than built on.

    start(game, variant)                    -> State
    judge(game, variant, history, move)     -> Ruling   (raises Illegal)
    flag_result(game, variant, history)     -> "white" | "black" | "draw"

Moves travel as UCI for chess ("e2e4", "e7e8q") and as numbered paths for
draughts ("32-28", "28x19x10").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import chess

from play import draughts


class Illegal(ValueError):
    pass


@dataclass
class State:
    position: str
    turn: str
    legal: list[str] = field(default_factory=list)


@dataclass
class Ruling:
    move: str
    san: str
    before: str
    after: State
    result: Optional[str] = None       # "white" | "black" | "draw"
    termination: Optional[str] = None


# -----------------------------------------------------------------------------
# Chess
# -----------------------------------------------------------------------------
_CHESS_END = {
    chess.Termination.CHECKMATE: "checkmate",
    chess.Termination.STALEMATE: "stalemate",
    chess.Termination.INSUFFICIENT_MATERIAL: "insufficient_material",
    chess.Termination.SEVENTYFIVE_MOVES: "fifty_moves",
    chess.Termination.FIFTY_MOVES: "fifty_moves",
    chess.Termination.FIVEFOLD_REPETITION: "repetition",
    chess.Termination.THREEFOLD_REPETITION: "repetition",
}


def _chess_board(history: list[str]) -> chess.Board:
    board = chess.Board()
    for uci in history:
        board.push_uci(uci)
    return board


def _chess_state(board: chess.Board) -> State:
    return State(
        position=board.fen(),
        turn="white" if board.turn == chess.WHITE else "black",
        legal=sorted(m.uci() for m in board.legal_moves),
    )


def _chess_judge(history: list[str], move: str) -> Ruling:
    board = _chess_board(history)
    before = board.fen()
    try:
        m = chess.Move.from_uci(move)
    except ValueError as e:
        raise Illegal(f"{move!r} is not a move") from e
    if m not in board.legal_moves:
        # A pawn reaching the last rank without saying what it becomes: the
        # board UI should always ask, but a queen is the answer people mean.
        queen = chess.Move(m.from_square, m.to_square, promotion=chess.QUEEN)
        if m.promotion is None and queen in board.legal_moves:
            m = queen
        else:
            raise Illegal(f"{move} is not legal here")
    san = board.san(m)
    board.push(m)
    # Draws by repetition and the fifty-move rule end the game at once rather
    # than waiting for a claim: online, nobody should have to know to ask.
    out = board.outcome(claim_draw=True)
    result = None
    if out is not None:
        result = "draw" if out.winner is None else ("white" if out.winner == chess.WHITE else "black")
    return Ruling(
        move=m.uci(),
        san=san,
        before=before,
        after=_chess_state(board),
        result=result,
        termination=_CHESS_END.get(out.termination) if out else None,
    )


def _chess_flag(history: list[str]) -> str:
    board = _chess_board(history)
    flagged = board.turn
    opponent = not flagged
    # Out of time loses - unless the opponent could never have mated.
    if board.has_insufficient_material(opponent):
        return "draw"
    return "white" if opponent == chess.WHITE else "black"


# -----------------------------------------------------------------------------
# Draughts
# -----------------------------------------------------------------------------
def _draughts_state(variant: str, pos: draughts.Position) -> State:
    return State(
        position=pos.fen(),
        turn=pos.turn,
        legal=[m.text for m in draughts.legal_moves(variant, pos)],
    )


def _draughts_judge(variant: str, history: list[str], move: str) -> Ruling:
    try:
        r = draughts.replay(variant, history)
    except ValueError as e:
        raise Illegal(str(e)) from e
    m = draughts.find(variant, r.position, move)
    if m is None:
        raise Illegal(f"{move} is not legal here")
    after = draughts.replay(variant, [*history, m.text])
    result, termination = draughts.outcome(variant, after)
    return Ruling(
        move=m.text,
        san=m.text,
        before=r.position.fen(),
        after=_draughts_state(variant, after.position),
        result=result,
        termination=termination,
    )


# -----------------------------------------------------------------------------
# The interface
# -----------------------------------------------------------------------------
def start(game: str, variant: str) -> State:
    if game == "chess":
        return _chess_state(chess.Board())
    return _draughts_state(variant, draughts.initial(variant))


def judge(game: str, variant: str, history: list[str], move: str) -> Ruling:
    if game == "chess":
        return _chess_judge(history, move)
    return _draughts_judge(variant, history, move)


def flag_result(game: str, variant: str, history: list[str]) -> str:
    if game == "chess":
        return _chess_flag(history)
    pos = draughts.replay(variant, history).position
    return "black" if pos.turn == "white" else "white"


def position_after(game: str, variant: str, history: list[str]) -> str:
    """The position a record leads to - compared with what the game stores."""
    if game == "chess":
        return _chess_board(history).fen()
    return draughts.replay(variant, history).position.fen()
