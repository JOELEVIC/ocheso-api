"""
What a person notices about a position and a move, from the board alone.

No engine here: material, phase, checks, captures, which way a piece moved,
whether a piece hangs. The brain mixes these with the engine's evaluations - a
person at 600 judges a move mostly by what is on this list; a person at 2000
mostly by what the engine would say.

MOVE ORDER MATTERS. The brain was calibrated in TypeScript on chess.js, and
several of its steps keep the order moves were generated in - ties in the human
prior, the candidate pool, the seeded weighted pick. `legal_moves` therefore
lists moves exactly as chess.js does (0x88 board order from a8, chess.js's
direction tables, knight-first promotions, castling last), using python-chess
only to decide legality. agents/golden holds the order to chess.js's on
hundreds of real positions.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional

import chess

VALUE = {chess.PAWN: 1, chess.KNIGHT: 3, chess.BISHOP: 3, chess.ROOK: 5, chess.QUEEN: 9, chess.KING: 0}
SYMBOL = {chess.PAWN: "p", chess.KNIGHT: "n", chess.BISHOP: "b", chess.ROOK: "r", chess.QUEEN: "q", chess.KING: "k"}

# chess.js's direction tables, on its 0x88 board (index = (7 - rank) * 16 + file).
_PAWN = {chess.WHITE: (-16, -32, -17, -15), chess.BLACK: (16, 32, 17, 15)}
_PIECE = {
    chess.KNIGHT: (-18, -33, -31, -14, 18, 33, 31, 14),
    chess.BISHOP: (-17, -15, 17, 15),
    chess.ROOK: (-16, 1, 16, -1),
    chess.QUEEN: (-17, -16, -15, 1, 17, 16, 15, -1),
    chess.KING: (-17, -16, -15, 1, 17, 16, 15, -1),
}
_PROMOTIONS = (chess.KNIGHT, chess.BISHOP, chess.ROOK, chess.QUEEN)


def _x88(sq: int) -> int:
    return (7 - chess.square_rank(sq)) * 16 + chess.square_file(sq)


def _sq(x: int) -> int:
    return chess.square(x & 7, 7 - (x >> 4))


def load(fen: str) -> chess.Board:
    return chess.Board(fen)


def legal_moves(board: chess.Board) -> list[chess.Move]:
    """Legal moves in chess.js's order."""
    us, them = board.turn, not board.turn
    pseudo: list[chess.Move] = []

    def add(frm: int, to: int, pawn: bool):
        if pawn and chess.square_rank(to) in (0, 7):
            for p in _PROMOTIONS:
                pseudo.append(chess.Move(frm, to, promotion=p))
        else:
            pseudo.append(chess.Move(frm, to))

    for x in range(0, 120):
        if x & 0x88:
            continue
        frm = _sq(x)
        piece = board.piece_at(frm)
        if piece is None or piece.color != us:
            continue
        if piece.piece_type == chess.PAWN:
            o = _PAWN[us]
            to = x + o[0]
            if not (to & 0x88) and board.piece_at(_sq(to)) is None:
                add(frm, _sq(to), True)
                to2 = x + o[1]
                second = 1 if us == chess.WHITE else 6
                if chess.square_rank(frm) == second and not (to2 & 0x88) and board.piece_at(_sq(to2)) is None:
                    add(frm, _sq(to2), True)
            for off in o[2:]:
                to = x + off
                if to & 0x88:
                    continue
                target = board.piece_at(_sq(to))
                if target is not None and target.color == them:
                    add(frm, _sq(to), True)
                elif board.ep_square is not None and _sq(to) == board.ep_square:
                    add(frm, _sq(to), True)
        else:
            for off in _PIECE[piece.piece_type]:
                to = x
                while True:
                    to += off
                    if to & 0x88:
                        break
                    target = board.piece_at(_sq(to))
                    if target is None:
                        add(frm, _sq(to), False)
                    else:
                        if target.color != us:
                            add(frm, _sq(to), False)
                        break
                    if piece.piece_type in (chess.KNIGHT, chess.KING):
                        break
    king = board.king(us)
    if king is not None:
        rank = 0 if us == chess.WHITE else 7
        if board.has_kingside_castling_rights(us):
            pseudo.append(chess.Move(king, chess.square(6, rank)))
        if board.has_queenside_castling_rights(us):
            pseudo.append(chess.Move(king, chess.square(2, rank)))
    seen = set()
    out = []
    for m in pseudo:
        if m in seen:
            continue
        seen.add(m)
        if board.is_legal(m):
            out.append(m)
    return out


def uci_of(m: chess.Move) -> str:
    return m.uci()


def _file(sq: str) -> int:
    return "abcdefgh".index(sq[0])


def _rank(sq: str) -> int:
    return int(sq[1]) - 1


def _near(a: str, b: str, d: int) -> bool:
    return max(abs(_file(a) - _file(b)), abs(_rank(a) - _rank(b))) <= d


def _non_pawn_material(board: chess.Board) -> int:
    total = 0
    for sq, p in board.piece_map().items():
        if p.piece_type not in (chess.PAWN, chess.KING):
            total += VALUE[p.piece_type]
    return total


def _material_for(board: chess.Board, color: bool) -> int:
    total = 0
    for p in board.piece_map().values():
        total += (1 if p.color == color else -1) * VALUE[p.piece_type]
    return total


@dataclass
class Position:
    fen: str
    history: list[str]
    prev_fen: Optional[str] = None


def _last_capture_square(pos: Position) -> Optional[str]:
    last = pos.history[-1] if pos.history else None
    if not last or not pos.prev_fen:
        return None
    to = last[2:4]
    before = load(pos.prev_fen).piece_at(chess.parse_square(to))
    board = load(pos.fen)
    # It was a capture if one of our pieces stood there before the move.
    return to if before is not None and before.color == board.turn else None


# The gauge decides thousands of times on one position; the board facts don't
# change between samples, so the last few positions are remembered.
_MEMO: "OrderedDict[str, object]" = OrderedDict()
_MEMO_SIZE = 64


def set_board_memo_size(n: int) -> None:
    global _MEMO_SIZE
    _MEMO_SIZE = max(16, n)


def _remember(key: str, make):
    if key in _MEMO:
        return _MEMO[key]
    value = make()
    _MEMO[key] = value
    if len(_MEMO) > _MEMO_SIZE:
        _MEMO.popitem(last=False)
    return value


def _key(kind: str, pos: Position) -> str:
    return f"{kind}|{pos.fen}|{pos.prev_fen or ''}|{pos.history[-1] if pos.history else ''}"


def position_facts(pos: Position) -> dict:
    return _remember(_key("p", pos), lambda: _compute_position_facts(pos))  # type: ignore[return-value]


def _compute_position_facts(pos: Position) -> dict:
    board = load(pos.fen)
    turn = board.turn
    moves = legal_moves(board)
    hanging = 0
    for sq, p in board.piece_map().items():
        if p.color != turn or p.piece_type == chess.KING:
            continue
        if board.attackers(not turn, sq) and not board.attackers(turn, sq):
            hanging += 1
    return {
        "turn": "w" if turn == chess.WHITE else "b",
        "legalCount": len(moves),
        "inCheck": board.is_check(),
        "phase": max(0, min(1, 1 - _non_pawn_material(board) / 62)),
        "material": _material_for(board, turn),
        "moveNumber": board.fullmove_number,
        "lastCaptureSquare": _last_capture_square(pos),
        "onlyMove": len(moves) == 1,
        "hangingPieces": hanging,
    }


def move_facts(pos: Position) -> "OrderedDict[str, dict]":
    """Facts about every legal move, keyed by UCI, in chess.js's order."""
    return _remember(_key("m", pos), lambda: _compute_move_facts(pos))  # type: ignore[return-value]


def _compute_move_facts(pos: Position, only: Optional[str] = None) -> "OrderedDict[str, dict]":
    board = load(pos.fen)
    turn = board.turn
    them = not turn
    enemy_king = board.king(them)
    own_king = board.king(turn)
    enemy_king_sq = chess.square_name(enemy_king) if enemy_king is not None else None
    own_king_sq = chess.square_name(own_king) if own_king is not None else None
    cap_sq = _last_capture_square(pos)
    opening = _non_pawn_material(board) >= 50
    out: "OrderedDict[str, dict]" = OrderedDict()

    for m in legal_moves(board):
        uci = m.uci()
        if only is not None and uci != only:
            continue
        piece = board.piece_at(m.from_square)
        assert piece is not None
        frm, to = chess.square_name(m.from_square), chess.square_name(m.to_square)
        forward = 1 if turn == chess.WHITE else -1
        d_rank = (_rank(to) - _rank(frm)) * forward
        dist = max(abs(_file(to) - _file(frm)), abs(_rank(to) - _rank(frm)))
        if board.is_en_passant(m):
            captured = chess.PAWN
        else:
            target = board.piece_at(m.to_square)
            captured = target.piece_type if target is not None and target.color == them else None
        naive_gain = (VALUE[captured] if captured else 0) + (VALUE[m.promotion] - 1 if m.promotion else 0)
        castle = board.is_castling(m)
        kingside = board.is_kingside_castling(m)
        san = board.san(m)

        board.push(m)
        is_check = board.is_check()
        is_mate = board.is_checkmate()
        # After the move it is the opponent's turn: is our piece safe?
        attackers = list(board.attackers(them, m.to_square))
        defenders = board.attackers(turn, m.to_square)
        moved_value = VALUE[m.promotion or piece.piece_type]
        cheapest = min([VALUE[board.piece_at(s).piece_type] or 100 for s in attackers] + [100])
        leaves_hanging = piece.piece_type != chess.KING and len(attackers) > 0 and (
            len(defenders) == 0 or cheapest < moved_value
        )
        # Threats: enemy pieces the moved piece now attacks that are undefended
        # or worth more than it.
        makes_threat = False
        for sq, p in board.piece_map().items():
            if p.color == turn or p.piece_type == chess.KING:
                continue
            if m.to_square not in board.attackers(turn, sq):
                continue
            if not board.attackers(them, sq) or VALUE[p.piece_type] > moved_value:
                makes_threat = True
                break
        board.pop()

        fact = {
            "uci": uci,
            "san": san,
            "piece": SYMBOL[piece.piece_type],
            "from": frm,
            "to": to,
        }
        if captured:
            fact["captured"] = SYMBOL[captured]
        if m.promotion:
            fact["promotion"] = SYMBOL[m.promotion]
        fact.update(
            {
                "naiveGain": naive_gain,
                "isCheck": is_check,
                "isMate": is_mate,
                "isCastle": castle,
                "isBackward": d_rank < 0,
                "isLongRange": piece.piece_type in (chess.BISHOP, chess.ROOK, chess.QUEEN) and dist >= 4,
                "nearEnemyKing": enemy_king_sq is not None and _near(to, enemy_king_sq, 2),
                "isPawnStorm": piece.piece_type == chess.PAWN
                and enemy_king_sq is not None
                and abs(_file(to) - _file(enemy_king_sq)) <= 1
                and not captured,
                "weakensOwnKing": piece.piece_type == chess.PAWN
                and own_king_sq is not None
                and not opening
                and _near(frm, own_king_sq, 1)
                and not captured,
                "isEvenTrade": captured is not None and VALUE[captured] == VALUE[piece.piece_type] and piece.piece_type != chess.PAWN,
                "makesThreat": makes_threat,
                "leavesHanging": leaves_hanging,
                "isRecapture": cap_sq is not None and to == cap_sq,
                "isDevelopment": opening
                and piece.piece_type in (chess.KNIGHT, chess.BISHOP)
                and _rank(frm) == (0 if turn == chess.WHITE else 7),
            }
        )
        out[uci] = fact
        del kingside
    return out


def play(pos: Position, uci: str) -> Optional[Position]:
    """The position after a UCI move, or None if it is not legal."""
    board = load(pos.fen)
    try:
        move = chess.Move.from_uci(uci)
    except ValueError:
        return None
    if move not in board.legal_moves:
        # chess.js accepts a pawn move to the last rank without a piece as a queen.
        if move.promotion is None and board.piece_type_at(move.from_square) == chess.PAWN and chess.square_rank(move.to_square) in (0, 7):
            move = chess.Move(move.from_square, move.to_square, promotion=chess.QUEEN)
            if move not in board.legal_moves:
                return None
        else:
            return None
    board.push(move)
    return Position(board.fen(), [*pos.history, uci], pos.fen)


def reply_traits(pos: Position, move: str, reply: str) -> Optional[dict]:
    """Facts about the opponent's best reply to a move - the refutation a person might miss."""
    return _remember(f"r|{pos.fen}|{move}|{reply}", lambda: _compute_reply_traits(pos, move, reply))  # type: ignore[return-value]


def _compute_reply_traits(pos: Position, move: str, reply: str) -> Optional[dict]:
    after = play(pos, move)
    if after is None:
        return None
    facts = _compute_move_facts(after, reply).get(reply)
    if facts is None:
        return None
    return {
        "capture": "captured" in facts,
        "check": facts["isCheck"],
        "backward": facts["isBackward"],
        "longRange": facts["isLongRange"],
        "knight": facts["piece"] == "n",
        "quiet": "captured" not in facts and not facts["isCheck"],
    }
