"""
Win percentage, and the engine's view of a position as the brain reads it.

Evaluations are felt in win-% (Lichess's curve): a pawn matters a lot at 0.0
and little at +8. The brain never talks to an engine directly; it keeps what
the engine said in a table - for every move, how good it looks at every depth
searched - and a person's "vision" is which depth they read the table at.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

K = 0.00368208
MATE_CP = 10000


def win_pct_from_cp(cp: float) -> float:
    return 50 + 50 * (2 / (1 + math.exp(-K * cp)) - 1)


def win_pct(cp: Optional[float] = None, mate: Optional[int] = None) -> float:
    """Win% for the side to move. A forced mate counts as (almost) certain."""
    if mate is not None:
        if mate > 0:
            return 100 - min(mate, 20) * 0.01
        if mate < 0:
            return 0 if max(-mate, 0) == 0 else min(-mate, 20) * 0.01
        return 0
    return win_pct_from_cp(cp or 0)


def cp_of(cp: Optional[float] = None, mate: Optional[int] = None) -> float:
    """Mates folded into centipawns: mate 3 -> 9997, mate -3 -> -9997."""
    if mate is not None:
        return MATE_CP - mate if mate > 0 else -MATE_CP - mate
    return cp or 0


def pct_of_cp(cp: float) -> float:
    if cp >= MATE_CP - 500:
        return win_pct(mate=MATE_CP - cp)
    if cp <= -MATE_CP + 500:
        return win_pct(mate=-(MATE_CP + cp))
    return win_pct(cp=cp)


@dataclass
class MoveEval:
    move: str
    cp_by_depth: dict[int, float] = field(default_factory=dict)
    reply: Optional[str] = None


@dataclass
class Analysis:
    fen: str
    history: list[str]
    moves: dict[str, MoveEval] = field(default_factory=dict)
    # Maia band -> move -> probability
    policy: dict[int, dict[str, float]] = field(default_factory=dict)
    max_depth: int = 0


def empty_analysis(fen: str, history: Optional[list[str]] = None) -> Analysis:
    return Analysis(fen, list(history or []))


def merge_search(a: Analysis, result: dict) -> Analysis:
    """Folds a search ({bestMove, byDepth: [{depth, lines: [{move, pv, scoreCp?, mate?}]}]})
    into the table. Deeper information about a move replaces its reply."""
    for level in result["byDepth"]:
        depth = level["depth"]
        for line in level["lines"]:
            if not line.get("move"):
                continue
            entry = a.moves.get(line["move"])
            if entry is None:
                entry = a.moves[line["move"]] = MoveEval(line["move"])
            entry.cp_by_depth[depth] = cp_of(line.get("scoreCp"), line.get("mate"))
            deepest = max(entry.cp_by_depth)
            pv = line.get("pv") or []
            if depth >= deepest and len(pv) > 1 and pv[1]:
                entry.reply = pv[1]
        a.max_depth = max(a.max_depth, depth)
    return a


def cp_at(entry: MoveEval, depth: float) -> Optional[float]:
    """The deepest evaluation at or below `depth`, else the shallowest there is."""
    best, best_depth = None, -1
    shallowest, shallowest_depth = None, math.inf
    for d, cp in entry.cp_by_depth.items():
        if d <= depth and d > best_depth:
            best, best_depth = cp, d
        if d < shallowest_depth:
            shallowest, shallowest_depth = cp, d
    return best if best is not None else shallowest


def cp_truth(entry: MoveEval) -> Optional[float]:
    """The evaluation at the deepest depth searched - the brain's "truth"."""
    d, v = -1, None
    for depth, cp in entry.cp_by_depth.items():
        if depth > d:
            d, v = depth, cp
    return v


def deepest_depth(entry: MoveEval) -> int:
    return max(entry.cp_by_depth) if entry.cp_by_depth else 0


def ranked(a: Analysis) -> list[dict]:
    """Moves ranked by truth, best first, with their win%. A move searched deeper
    is trusted over one only seen shallowly at the same score."""
    out = []
    for e in a.moves.values():
        cp = cp_truth(e)
        if cp is None:
            continue
        out.append({"move": e.move, "cp": cp, "pct": pct_of_cp(cp), "depth": deepest_depth(e)})
    return sorted(out, key=lambda m: (-m["cp"], -m["depth"]))


def snapshot(a: Analysis) -> dict:
    """A compact, JSON-safe copy: enough to replay a decision exactly."""
    moves = []
    for e in a.moves.values():
        pairs = sorted([[d, cp] for d, cp in e.cp_by_depth.items()], key=lambda p: p[0])
        moves.append([e.move, pairs, e.reply] if e.reply else [e.move, pairs])
    return {
        "fen": a.fen,
        "history": a.history,
        "moves": moves,
        "policy": [[band, p] for band, p in a.policy.items()],
        "maxDepth": a.max_depth,
    }


def from_snapshot(s: dict) -> Analysis:
    a = Analysis(s["fen"], list(s["history"]), max_depth=s["maxDepth"])
    for entry in s["moves"]:
        move, pairs = entry[0], entry[1]
        reply = entry[2] if len(entry) > 2 else None
        a.moves[move] = MoveEval(move, {int(d): cp for d, cp in pairs}, reply)
    for band, p in s["policy"]:
        a.policy[int(band)] = p
    return a
