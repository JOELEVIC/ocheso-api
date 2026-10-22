"""
Draughts, by the FMJD rules: international on 10×10, Brazilian on 8×8.

Brazilian is the international rule set on the smaller board, so one engine
plays both. The rules that matter, each of which a casual implementation gets
wrong:

  * Capturing is compulsory, and you must take the MOST pieces available
    (men and kings count the same). Among equal-length captures you choose.
  * Men move forward one square but capture forward and backward.
  * Kings fly: any distance along a diagonal, and capture from a distance,
    landing on any empty square beyond the captured piece.
  * Turkish strike: captured pieces leave the board only when the move ends.
    Until then they block, and none may be jumped twice.
  * A man is crowned only if it ENDS its move on the far row. Passing through
    it during a capture and carrying on does not crown it.
  * Losing: having no legal move (which includes having no pieces).
  * Drawn: the same position with the same side to move for the third time,
    or 25 moves each made only with kings, without a capture.

Squares are numbered as in published games: 1 at the top left dark square
(Black's side), counting left to right, top to bottom. White starts at the
bottom and moves up.

Positions are PDN FEN: "W:W31,32,K45:B1,2" - side to move, then each side's
pieces, K marking kings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

WHITE, BLACK = "white", "black"
DIRS = ((-1, -1), (-1, 1), (1, -1), (1, 1))


@dataclass(frozen=True)
class Board:
    size: int  # 10 or 8

    @property
    def per_row(self) -> int:
        return self.size // 2

    @property
    def squares(self) -> int:
        return self.size * self.size // 2

    def rc(self, n: int) -> tuple[int, int]:
        i = n - 1
        r = i // self.per_row
        return r, 2 * (i % self.per_row) + (1 if r % 2 == 0 else 0)

    def num(self, r: int, c: int) -> Optional[int]:
        if not (0 <= r < self.size and 0 <= c < self.size) or (r + c) % 2 == 0:
            return None
        return r * self.per_row + c // 2 + 1

    def step(self, n: int, d: tuple[int, int]) -> Optional[int]:
        r, c = self.rc(n)
        return self.num(r + d[0], c + d[1])


BOARDS = {"international": Board(10), "brazilian": Board(8)}


def board_for(variant: str) -> Board:
    try:
        return BOARDS[variant]
    except KeyError as e:
        raise ValueError(f"no draughts variant called {variant!r}") from e


# -----------------------------------------------------------------------------
# Positions
# -----------------------------------------------------------------------------
@dataclass
class Position:
    pieces: dict[int, str]  # square -> 'w', 'W', 'b', 'B' (capitals are kings)
    turn: str

    def copy(self) -> "Position":
        return Position(dict(self.pieces), self.turn)

    def fen(self) -> str:
        def side(colour: str) -> str:
            own = sorted(sq for sq, p in self.pieces.items() if p.lower() == colour)
            return ",".join(("K" if self.pieces[sq].isupper() else "") + str(sq) for sq in own)

        return f"{'W' if self.turn == WHITE else 'B'}:W{side('w')}:B{side('b')}"


def initial(variant: str) -> Position:
    b = board_for(variant)
    rows = 4 if b.size == 10 else 3
    black = range(1, rows * b.per_row + 1)
    white = range(b.squares - rows * b.per_row + 1, b.squares + 1)
    pieces = {sq: "b" for sq in black} | {sq: "w" for sq in white}
    return Position(pieces, WHITE)


def parse(fen: str) -> Position:
    try:
        turn, *sides = fen.strip().split(":")
        pieces: dict[int, str] = {}
        for s in sides:
            colour, body = s[0].lower(), s[1:]
            for token in filter(None, body.split(",")):
                king = token.startswith("K")
                sq = int(token[1:] if king else token)
                pieces[sq] = colour.upper() if king else colour
        return Position(pieces, WHITE if turn.upper() == "W" else BLACK)
    except (ValueError, IndexError) as e:
        raise ValueError(f"not a draughts position: {fen!r}") from e


# -----------------------------------------------------------------------------
# Moves
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class Move:
    path: tuple[int, ...]          # origin, then each landing square
    captured: tuple[int, ...]      # in the order taken

    @property
    def text(self) -> str:
        return ("x" if self.captured else "-").join(str(sq) for sq in self.path)


def _own(piece: str, turn: str) -> bool:
    return piece.lower() == ("w" if turn == WHITE else "b")


def _forward(turn: str) -> int:
    return -1 if turn == WHITE else 1


def _captures_from(b: Board, pos: Position, origin: int) -> list[Move]:
    piece = pos.pieces[origin]
    king = piece.isupper()
    found: list[Move] = []

    def empty(sq: int) -> bool:
        # The moving piece has left its square; anything else there blocks.
        return sq == origin or sq not in pos.pieces

    def enemy(sq: int) -> bool:
        return sq in pos.pieces and sq != origin and not _own(pos.pieces[sq], pos.turn)

    def walk(at: int, path: tuple[int, ...], taken: tuple[int, ...]) -> None:
        extended = False
        for d in DIRS:
            if king:
                # Slide over empty squares to the first piece on this line.
                sq = b.step(at, d)
                while sq is not None and empty(sq):
                    sq = b.step(sq, d)
                if sq is None or not enemy(sq) or sq in taken:
                    continue
                victim = sq
                land = b.step(victim, d)
                while land is not None and empty(land):
                    extended = True
                    walk(land, path + (land,), taken + (victim,))
                    land = b.step(land, d)
            else:
                victim = b.step(at, d)
                if victim is None or not enemy(victim) or victim in taken:
                    continue
                land = b.step(victim, d)
                if land is None or not empty(land):
                    continue
                extended = True
                walk(land, path + (land,), taken + (victim,))
        if not extended and taken:
            found.append(Move(path, taken))

    walk(origin, (origin,), ())
    return found


def _slides_from(b: Board, pos: Position, origin: int) -> list[Move]:
    piece = pos.pieces[origin]
    out: list[Move] = []
    for d in DIRS:
        if piece.isupper():
            sq = b.step(origin, d)
            while sq is not None and sq not in pos.pieces:
                out.append(Move((origin, sq), ()))
                sq = b.step(sq, d)
        elif d[0] == _forward(pos.turn):
            sq = b.step(origin, d)
            if sq is not None and sq not in pos.pieces:
                out.append(Move((origin, sq), ()))
    return out


def legal_moves(variant: str, pos: Position) -> list[Move]:
    b = board_for(variant)
    mine = [sq for sq, p in pos.pieces.items() if _own(p, pos.turn)]
    captures = [m for sq in mine for m in _captures_from(b, pos, sq)]
    if captures:
        most = max(len(m.captured) for m in captures)
        best = [m for m in captures if len(m.captured) == most]
        # Two routes can land on the same squares taking different pieces; the
        # text names the route, so keep the first of each.
        seen: dict[str, Move] = {}
        for m in best:
            seen.setdefault(m.text, m)
        return sorted(seen.values(), key=lambda m: m.path)
    return sorted((m for sq in mine for m in _slides_from(b, pos, sq)), key=lambda m: m.path)


def apply(variant: str, pos: Position, move: Move) -> Position:
    b = board_for(variant)
    nxt = pos.copy()
    piece = nxt.pieces.pop(move.path[0])
    for sq in move.captured:
        del nxt.pieces[sq]
    end = move.path[-1]
    far_row = 0 if pos.turn == WHITE else b.size - 1
    if piece.islower() and b.rc(end)[0] == far_row:
        piece = piece.upper()
    nxt.pieces[end] = piece
    nxt.turn = BLACK if pos.turn == WHITE else WHITE
    return nxt


def find(variant: str, pos: Position, text: str) -> Optional[Move]:
    text = text.strip().replace(" ", "")
    for m in legal_moves(variant, pos):
        if m.text == text:
            return m
    return None


# -----------------------------------------------------------------------------
# Games
# -----------------------------------------------------------------------------
@dataclass
class Replay:
    """A game rebuilt from its moves: the position, and what decides draws."""

    position: Position
    seen: dict[str, int]
    quiet_king_plies: int  # consecutive king moves without a capture, both sides


def replay(variant: str, moves: Iterable[str]) -> Replay:
    pos = initial(variant)
    seen = {pos.fen(): 1}
    quiet = 0
    for text in moves:
        m = find(variant, pos, text)
        if m is None:
            raise ValueError(f"illegal move in the record: {text}")
        moved_king = pos.pieces[m.path[0]].isupper()
        pos = apply(variant, pos, m)
        quiet = quiet + 1 if moved_king and not m.captured else 0
        seen[pos.fen()] = seen.get(pos.fen(), 0) + 1
    return Replay(pos, seen, quiet)


def outcome(variant: str, r: Replay) -> tuple[Optional[str], Optional[str]]:
    """(result, termination) for the position reached, or (None, None)."""
    if not legal_moves(variant, r.position):
        # No move - blocked or no pieces left - loses.
        return (BLACK if r.position.turn == WHITE else WHITE), "no_moves"
    if r.seen.get(r.position.fen(), 0) >= 3:
        return "draw", "repetition"
    if r.quiet_king_plies >= 50:
        return "draw", "twenty_five_moves"
    return None, None
