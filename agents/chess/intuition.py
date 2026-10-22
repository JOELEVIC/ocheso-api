"""
Intuition - which moves a person of this level even considers - and the book.

With Maia loaded, the prior is Maia's policy for the nearest band (below its
lowest band, flattened toward a beginner's scattered attention). Without it, a
heuristic prior from the board alone: people capture, check, recapture, develop
and castle; they rarely play quiet backward moves or walk the king.
"""

from __future__ import annotations

import math
import re
from typing import Optional

from agents.chess.priors import Priors
from agents.jsmath import clamp, js_round
from agents.rng import Rng

_CENTRE = re.compile(r"[de][45]")


def maia_band(rating: float, priors: Priors) -> int:
    """The Maia band a rating reads: 1100 ... 1900 in hundreds."""
    return int(clamp(js_round(rating / 100) * 100, priors.maia_floor, priors.maia_ceiling))


def _normalise(weights: dict[str, float]) -> dict[str, float]:
    total = sum(weights.values())
    return {k: (w / total if total > 0 else 1 / len(weights)) for k, w in weights.items()}


def heuristic_prior(rating: float, pos: dict, facts: dict[str, dict]) -> dict[str, float]:
    """A prior from the board alone."""
    # How much a person of this level avoids leaving a piece en prise at a glance.
    hang_aversion = clamp((rating - 300) / 1000, 0, 1.4)
    weights: dict[str, float] = {}
    for f in facts.values():
        logit = 0.0
        if "captured" in f:
            logit += 1.0 + 0.2 * f["naiveGain"]
        if f["isRecapture"]:
            logit += 2.0
        if f["isCheck"]:
            logit += 0.8
        if f["isMate"]:
            logit += 1.5 + clamp((rating - 400) / 400, 0, 3)
        if f["isCastle"]:
            logit += 1.2
        if f["isDevelopment"]:
            logit += 0.9
        if f["piece"] == "p" and pos["phase"] < 0.3 and _CENTRE.search(f["to"]):
            logit += 0.6
        if f["piece"] == "k" and not f["isCastle"] and pos["phase"] < 0.6:
            logit -= 1.2
        if f["piece"] == "q" and pos["phase"] < 0.15 and pos["moveNumber"] < 8:
            logit -= 0.5
        if f["isBackward"]:
            logit -= 0.5
        if f["makesThreat"]:
            logit += 0.5
        if f["leavesHanging"]:
            logit -= hang_aversion
        promo = f.get("promotion")
        if promo == "q":
            logit += 2
        elif promo:
            logit -= 2
        weights[f["uci"]] = math.exp(logit)
    return _normalise(weights)


def adjust_policy(policy: dict[str, float], rating: float, priors: Priors) -> dict[str, float]:
    """Maia's policy for a rating outside its bands: flattened below its floor
    (a beginner considers more of the board at random), sharpened above its ceiling."""
    power = 1.0
    if rating < priors.maia_floor:
        power = 1 / (1 + (priors.maia_floor - rating) / 600)
    elif rating > priors.maia_ceiling:
        power = 1 + min(0.6, (rating - priors.maia_ceiling) / 1000)
    return _normalise({m: max(p, 1e-6) ** power for m, p in policy.items()})


def prior_for(rating: float, priors: Priors, pos: dict, facts: dict[str, dict],
              policy_by_band: dict[int, dict[str, float]]) -> tuple[dict[str, float], str]:
    """The prior a person of this rating brings to the position, and its source."""
    policy = policy_by_band.get(maia_band(rating, priors))
    if policy:
        adjusted = adjust_policy(policy, rating, priors)
        # Below Maia's floor, blend in the board heuristic: beginners grab and check.
        if rating < priors.maia_floor:
            h = heuristic_prior(rating, pos, facts)
            mix = clamp((priors.maia_floor - rating) / 900, 0, 0.6)
            blended = {m: (1 - mix) * adjusted.get(m, 0) + mix * h.get(m, 0) for m in facts}
            return _normalise(blended), "maia"
        return adjusted, "maia"
    return heuristic_prior(rating, pos, facts), "heuristic"


def book_move(p: dict, history: list[str], own_move: int, rng: Rng) -> Optional[str]:
    """The next move of a repertoire line, while the game follows one."""
    o = p["play"]["openings"]
    if own_move >= o["bookDepth"]:
        return None
    white = len(history) % 2 == 0
    if white:
        lines = o["white"]
    elif history[0] == "e2e4":
        lines = o["blackVsE4"]
    elif history[0] == "d2d4":
        lines = o["blackVsD4"]
    else:
        lines = o["blackVsOther"]
    nxt = []
    for line in lines:
        moves = line["moves"].split(" ")
        if len(moves) <= len(history):
            continue
        if all(moves[i] == m for i, m in enumerate(history)):
            nxt.append({"move": moves[len(history)], "weight": line["weight"]})
    if not nxt:
        return None
    if rng.chance(o["misremember"]):
        return None
    return nxt[rng.weighted([n["weight"] for n in nxt])]["move"]
