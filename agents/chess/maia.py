"""
Maia, as the brain reads it - what a person at a rating would play here.

Maia (CSSLab, GPL-3.0) is a set of Leela Chess Zero networks trained on
millions of Lichess games, one per rating band 1100-1900. This module is the
pure part: a position and its last moves into the 112 input planes lc0's
"classical" networks read, and the 1858 policy outputs back into probabilities
over the legal moves. Running the network is onnxruntime's job (engines.py).

Encoding (lc0 INPUT_CLASSICAL_112_PLANE), from the side to move's point of view,
the board mirrored when Black is to move: eight positions of history, newest
first, 13 planes each (our P N B R Q K, their P N B R Q K, "occurred before"),
then our O-O-O, our O-O, their O-O-O, their O-O, Black to move, the fifty-move
counter, zeros, ones.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

import chess

from agents.chess.board import legal_moves

MAIA_BANDS = (1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900)
MAIA_PLANES = 112
MAIA_POLICY_SIZE = 1858
STANDARD_FEN = chess.STARTING_FEN

_FILES = "abcdefgh"
_TABLE: Optional[list[str]] = None
_INDEX: Optional[dict[str, int]] = None


def _sq_name(f: int, r: int) -> str:
    return f"{_FILES[f]}{r + 1}"


def policy_moves() -> list[str]:
    """lc0's 1858 policy moves, in order (White's point of view)."""
    global _TABLE, _INDEX
    if _TABLE is not None:
        return _TABLE
    out: list[str] = []
    for r in range(8):
        for f in range(8):
            for r2 in range(8):
                for f2 in range(8):
                    if f2 == f and r2 == r:
                        continue
                    df, dr = f2 - f, r2 - r
                    queen = df == 0 or dr == 0 or abs(df) == abs(dr)
                    knight = (abs(df) == 1 and abs(dr) == 2) or (abs(df) == 2 and abs(dr) == 1)
                    if queen or knight:
                        out.append(_sq_name(f, r) + _sq_name(f2, r2))
    for f in range(8):
        for df in (-1, 0, 1):
            f2 = f + df
            if not 0 <= f2 <= 7:
                continue
            for p in ("q", "r", "b"):
                out.append(_sq_name(f, 6) + _sq_name(f2, 7) + p)
    _TABLE = out
    _INDEX = {m: i for i, m in enumerate(out)}
    return out


def _mirror(sq: str) -> str:
    return f"{sq[0]}{9 - int(sq[1])}"


def policy_key(uci: str, mover_is_black: bool, castle: Optional[str]) -> str:
    """How lc0 names a legal move in its policy, from the mover's point of view."""
    frm, to = uci[0:2], uci[2:4]
    # lc0 thinks of castling as the king taking its own rook (e1h1, e1a1).
    if castle:
        to = f"{'h' if castle == 'O-O' else 'a'}{to[1]}"
    if mover_is_black:
        frm, to = _mirror(frm), _mirror(to)
    promo = uci[4] if len(uci) > 4 else ""
    return f"{frm}{to}{promo}" if promo and promo != "n" else f"{frm}{to}"


def _key4(fen: str) -> str:
    return " ".join(fen.split(" ")[:4])


def maia_history(start_fen: Optional[str], moves: Sequence[str], fen: str) -> dict:
    """The positions to encode, newest first: the current one and those before it."""
    board = chess.Board(start_fen) if start_fen else chess.Board()
    fens = [board.fen()]
    for m in moves:
        try:
            move = chess.Move.from_uci(m)
        except ValueError:
            return {"fens": [fen], "fromStandardStart": False}
        if move not in board.legal_moves:
            return {"fens": [fen], "fromStandardStart": False}
        board.push(move)
        fens.append(board.fen())
    # The replay must arrive where we are; if it doesn't, trust only the position.
    if _key4(fens[-1]) != _key4(fen):
        return {"fens": [fen], "fromStandardStart": False}
    return {"fens": list(reversed(fens)), "fromStandardStart": start_fen is None}


_PIECES = (chess.PAWN, chess.KNIGHT, chess.BISHOP, chess.ROOK, chess.QUEEN, chess.KING)


def maia_input(fens: Sequence[str], from_standard_start: bool) -> list[float]:
    """The 112x8x8 input, laid out [plane][rank][file]."""
    out = [0.0] * (MAIA_PLANES * 64)
    boards = [chess.Board(f) for f in list(fens)[:8]]
    current = boards[0]
    us = current.turn

    def fill(plane: int, value: float = 1.0) -> None:
        out[plane * 64:(plane + 1) * 64] = [value] * 64

    keys = [_key4(f) for f in fens]
    reps = [len([k for k in keys[i + 1:] if k == keys[i]]) for i in range(len(boards))]
    # Before the first known position lc0 leaves zeros when that position is
    # the standard start, and otherwise repeats the last block it encoded.
    fill_empty = not from_standard_start and keys[-1] != _key4(STANDARD_FEN)
    flip = False
    for h in range(8):
        if h >= len(boards):
            if not fill_empty:
                break
            out[h * 13 * 64:(h + 1) * 13 * 64] = out[(h - 1) * 13 * 64:h * 13 * 64]
            continue
        b = boards[h]
        persp = (not b.turn) if flip else b.turn
        base = h * 13
        for sq, piece in b.piece_map().items():
            f = chess.square_file(sq)
            r = chess.square_rank(sq)
            if persp == chess.BLACK:
                r = 7 - r
            plane = base + (0 if piece.color == persp else 6) + _PIECES.index(piece.piece_type)
            out[plane * 64 + r * 8 + f] = 1.0
        if reps[h] >= 1:
            fill(base + 12)
        flip = not flip

    if current.has_queenside_castling_rights(us):
        fill(104)
    if current.has_kingside_castling_rights(us):
        fill(105)
    if current.has_queenside_castling_rights(not us):
        fill(106)
    if current.has_kingside_castling_rights(not us):
        fill(107)
    if us == chess.BLACK:
        fill(108)
    fill(109, float(fens[0].split(" ")[4]) if len(fens[0].split(" ")) > 4 else 0.0)
    fill(111)
    return out


def maia_policy(logits: Sequence[float], fen: str, temperature: float = 1) -> dict[str, float]:
    """Probabilities over the legal moves from the network's 1858 policy logits."""
    if _INDEX is None:
        policy_moves()
    board = chess.Board(fen)
    black = board.turn == chess.BLACK
    scored = []
    top = -math.inf
    for m in legal_moves(board):
        castle = None
        if board.is_kingside_castling(m):
            castle = "O-O"
        elif board.is_queenside_castling(m):
            castle = "O-O-O"
        uci = m.uci()
        i = _INDEX.get(policy_key(uci, black, castle))  # type: ignore[union-attr]
        if i is None:
            continue
        v = logits[i] / temperature
        scored.append((uci, v))
        if v > top:
            top = v
    out: dict[str, float] = {}
    total = 0.0
    for uci, v in scored:
        e = math.exp(v - top)
        out[uci] = e
        total += e
    return {k: v / total for k, v in out.items()}
