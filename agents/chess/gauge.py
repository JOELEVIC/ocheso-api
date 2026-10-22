"""
How hard is this position - for a person, at each rating?

One analysis of the position, then the "typical person at rating R" decides it
N times per rating band - the same `decide` an agent plays with, so the gauge
and the players can never disagree. From the samples: how often each band finds
the best move, a good move, or blunders; how long they take (p10/p50/p90) at a
chosen cadence; and which moves they actually play.

The headline is a difficulty rating: the rating at which half of people find
the best move, on the same scale as a puzzle rating.
"""

from __future__ import annotations

import math
from typing import Optional

from agents.chess.analysis import MATE_CP, Analysis, cp_at, ranked
from agents.chess.archetypes import typical_persona
from agents.chess.board import Position, move_facts
from agents.chess.decide import character, decide
from agents.chess.priors import PRIORS, Priors
from agents.jsmath import js_round
from agents.mood import start_game
from agents.persona import parse_cadence
from agents.rng import rng_from

DEFAULT_GAUGE_RATINGS = [200, 400, 600, 800, 1000, 1200, 1400, 1600, 1800, 2000, 2200, 2400]


def _quantile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0
    return sorted_values[min(len(sorted_values) - 1, max(0, math.floor(q * (len(sorted_values) - 1))))]


def solution_depth(a: Analysis, best: str) -> Optional[int]:
    """The shallowest depth from which the best move stays best."""
    depths = sorted({d for e in a.moves.values() for d in e.cp_by_depth})
    answer = None
    for d in reversed(depths):
        top, top_cp = None, -math.inf
        for e in a.moves.values():
            if d not in e.cp_by_depth:
                continue
            cp = cp_at(e, d)
            if cp > top_cp:
                top, top_cp = e.move, cp
        if top == best:
            answer = d
        else:
            break
    return answer


def gauge(
    a: Analysis,
    *,
    ratings: Optional[list[int]] = None,
    samples: int = 200,
    cadence: str = "10+0",
    seed: Optional[str] = None,
    priors: Priors = PRIORS,
    own_move: int = 15,
    good_within_pct: float = 5,
    blunder_pct: float = 20,
    clock_ms: Optional[float] = None,
) -> dict:
    """`clock_ms` is the time the mover has left (default: 70% of the base, no
    pressure); a low clock brings time trouble, as in play."""
    ratings = ratings or DEFAULT_GAUGE_RATINGS
    cad = parse_cadence(cadence)
    clock = clock_ms if clock_ms is not None else cad["baseSec"] * 1000 * 0.7
    seed = seed if seed is not None else a.fen
    r = ranked(a)
    best = r[0] if r else None
    facts = move_facts(Position(a.fen, a.history))
    shape = character(a, facts)
    pct_of = {m["move"]: m["pct"] for m in r}
    cp_of_move = {m["move"]: m["cp"] for m in r}
    # "Best" is the best move or one as good: within a win-% point, or - when
    # the best is a forced mate - a mate at least as fast.
    best_is_mate = best is not None and best["cp"] >= MATE_CP - 500

    def is_best(move: str) -> bool:
        if not best:
            return False
        if move == best["move"]:
            return True
        cp = cp_of_move.get(move)
        if cp is None:
            return False
        return cp >= best["cp"] if best_is_mate else best["pct"] - pct_of[move] <= 1

    prior_source = "heuristic"
    bands = []
    for rating in ratings:
        persona = typical_persona(rating)
        best_count = good_count = blunder_count = 0
        times: list[float] = []
        counts: dict[str, int] = {}
        for i in range(samples):
            rng = rng_from(f"{seed}/gauge/{rating}/{i}")
            mood = start_game(persona, 0, rating, rng.fork("mood"))
            d = decide(
                a,
                persona=persona,
                priors=priors,
                mood=mood,
                rng=rng,
                own_move=own_move,
                clock_ms=clock,
                cadence=cad,
                from_start=False,
            )
            prior_source = d["priorSource"]
            times.append(d["thinkMs"])
            counts[d["move"]] = counts.get(d["move"], 0) + 1
            loss = best["pct"] - pct_of[d["move"]] if best and d["move"] in pct_of else 0
            if is_best(d["move"]):
                best_count += 1
            if loss <= good_within_pct:
                good_count += 1
            if loss >= blunder_pct:
                blunder_count += 1
        times.sort()
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:6]
        bands.append(
            {
                "rating": rating,
                "pBest": best_count / samples,
                "pGood": good_count / samples,
                "pBlunder": blunder_count / samples,
                "thinkMs": {"p10": _quantile(times, 0.1), "p50": _quantile(times, 0.5), "p90": _quantile(times, 0.9)},
                "moves": [{"move": m, "san": facts[m]["san"] if m in facts else m, "p": n / samples} for m, n in top],
            }
        )

    def crossing(key: str) -> Optional[int]:
        if not bands or bands[0][key] >= 0.5:
            return None
        for i in range(1, len(bands)):
            lo, hi = bands[i - 1], bands[i]
            if lo[key] < 0.5 <= hi[key]:
                return js_round(lo["rating"] + ((0.5 - lo[key]) / (hi[key] - lo[key])) * (hi["rating"] - lo["rating"]))
        return None

    difficulty = None
    out_of_range = None
    if bands and bands[0]["pBest"] >= 0.5:
        out_of_range = "easier"
    else:
        difficulty = crossing("pBest")
        if difficulty is None:
            out_of_range = "harder"

    return {
        "fen": a.fen,
        "goodDifficulty": crossing("pGood"),
        "bestMove": best["move"] if best else None,
        "bestSan": (facts[best["move"]]["san"] if best["move"] in facts else best["move"]) if best else None,
        "bestPct": best["pct"] if best else 50,
        "goodMoves": len([m for m in r if best["pct"] - m["pct"] <= good_within_pct]) if best else 0,
        "bestMoves": [m["move"] for m in r if is_best(m["move"])],
        "criticality": shape["criticality"],
        "complexity": shape["complexity"],
        "onlyMove": len(facts) == 1,
        "solutionDepth": solution_depth(a, best["move"]) if best else None,
        "difficulty": difficulty,
        "outOfRange": out_of_range,
        "priorSource": prior_source,
        "bands": bands,
    }
