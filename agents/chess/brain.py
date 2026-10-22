"""
The brain's one engine step: asking the engines about a position.

Two searches, sized by a budget. A shallow pass over every legal move (so every
candidate a person might consider has a value at every shallow depth), then a
deeper look at the few moves that matter - the engine's best and the ones people
at this level tend to play - with `searchmoves`. Plus Maia's policy for each
band asked for, when a Maia model is available.

Everything after this is `decide` - pure. An engine is anything with
`search(request) -> {bestMove, byDepth}` and, optionally,
`policy(fen, history, band) -> {move: p} | None` (agents/engines.py).
"""

from __future__ import annotations

import math
from typing import Any, Optional

import chess

from agents.chess.analysis import Analysis, empty_analysis, merge_search, ranked
from agents.chess.intuition import maia_band
from agents.chess.priors import PRIORS, Priors
from agents.jsmath import clamp, js_round


def budget_for(rating: float, priors: Priors = PRIORS, cap: int = 16) -> dict:
    """What a person of this rating needs searched: a little beyond what they can see."""
    vision = priors.vision_depth(rating)
    return {"shallowDepth": 4, "deepDepth": int(clamp(js_round(vision) + 5, 7, cap)), "deepCount": 6}


def analyse_position(engine: Any, fen: str, history: list[str], *, ratings: list[float],
                     budget: dict, priors: Optional[Priors] = None) -> Analysis:
    priors = priors or PRIORS
    a = empty_analysis(fen, history)
    legal = chess.Board(fen).legal_moves.count()
    if legal == 0:
        return a

    policy = getattr(engine, "policy", None)
    if policy is not None:
        bands = list(dict.fromkeys(maia_band(r, priors) for r in ratings))
        for band in bands:
            p = policy(fen, history, band)
            if p:
                a.policy[band] = p

    merge_search(
        a,
        engine.search(
            {
                "fen": fen,
                "depth": budget["shallowDepth"],
                "multiPv": min(legal, 64),
                "nodes": budget.get("nodes"),
                "movetimeMs": budget.get("movetimeMs"),
            }
        ),
    )
    if legal == 1:
        return a

    deep: dict[str, None] = {}
    for m in ranked(a)[: math.ceil(budget["deepCount"] / 2)]:
        deep[m["move"]] = None
    for p in a.policy.values():
        for m, _ in sorted(p.items(), key=lambda kv: -kv[1])[:3]:
            deep[m] = None
    search_moves = list(deep)[: budget["deepCount"] + 2]
    if budget["deepDepth"] > budget["shallowDepth"] and search_moves:
        merge_search(
            a,
            engine.search(
                {
                    "fen": fen,
                    "depth": budget["deepDepth"],
                    "multiPv": len(search_moves),
                    "searchMoves": search_moves,
                    "nodes": budget.get("nodes"),
                    "movetimeMs": budget.get("movetimeMs"),
                }
            ),
        )
    return a
