"""
Who takes a seat, and when - the rules that keep people first.

A seek is a person waiting for a game on the client's platform. An agent only
steps in after a wait long enough that a person could have come (8-30 s by
default, drawn per seek so it never looks timed), never while another
compatible person is seeking the same cadence, never for a stale seek (an app
gone to the background) or a position seek. Then it picks an online, idle
agent who plays that cadence, within a rating window that widens with the wait
(set it to the platform's own pairing window, so an agent is never a closer
match than a person would have been), nearer ratings likelier, and rarely the
same agent twice running against the same person.

Pure: the connector gathers the facts, the platform re-checks them when the
seat is taken, and this decides. Ported from the TypeScript kit and held to it
exactly (tests/test_dispatch.py).
"""

from __future__ import annotations

import math
from typing import Any

from agents.jsmath import js_round
from agents.rng import Rng, rng_from

DEFAULT_RATING_WINDOW = {"start": 150, "step": 50, "stepMs": 10_000, "anyoneAfterMs": 60_000}

DEFAULT_DISPATCH = {
    "waitMinMs": 8_000,
    "waitMaxMs": 30_000,
    "maxHeartbeatAgeMs": 20_000,
    "repeatPenalty": 3,
    "cadences": ["5+0", "5+3", "10+0", "10+5", "15+10", "30+0"],
    "ratingWindow": DEFAULT_RATING_WINDOW,
}


def rating_window(age_ms: float, w: dict = DEFAULT_RATING_WINDOW) -> float:
    """The rating gap a seek of this age accepts."""
    if age_ms >= w["anyoneAfterMs"]:
        return math.inf
    return w["start"] + w["step"] * math.floor(max(0, age_ms) / w["stepMs"])


def wait_for(seek_id: str, s: dict) -> int:
    """How long this particular seek waits for a person before an agent considers it."""
    return js_round(rng_from(f"wait/{seek_id}").between(s["waitMinMs"], s["waitMaxMs"]))


def decide_seat(seek: dict, agents: list[dict], now_ms: float, s: dict, rng: Rng) -> dict:
    """seek: {id, creatorId, creatorRating, cadence, createdAtMs, heartbeatAtMs,
    isPosition, humanAlternatives}; agents: [{id, rating, persona, online, idle,
    recentOpponents}]."""
    if seek["isPosition"]:
        return {"action": "skip", "reason": "position-seek"}
    if seek["cadence"] not in s["cadences"]:
        return {"action": "skip", "reason": "cadence-off"}
    if now_ms - seek["heartbeatAtMs"] > s["maxHeartbeatAgeMs"]:
        return {"action": "skip", "reason": "stale"}
    age = now_ms - seek["createdAtMs"]
    wait = wait_for(seek["id"], s)
    if age < wait:
        return {"action": "wait", "reason": "people-first-window", "retryInMs": wait - age}
    if seek["humanAlternatives"] > 0:
        return {"action": "wait", "reason": "a-person-could-pair", "retryInMs": 5_000}

    window = rating_window(age, s.get("ratingWindow", DEFAULT_RATING_WINDOW))
    eligible = [
        m for m in agents
        if m["online"] and m["idle"] and seek["cadence"] in m["persona"]["life"]["cadences"]
        and abs(m["rating"] - seek["creatorRating"]) <= window
    ]
    if not eligible:
        return {"action": "wait", "reason": "nobody-suitable", "retryInMs": 5_000}
    weights = []
    for m in eligible:
        gap = abs(m["rating"] - seek["creatorRating"])
        recent = m.get("recentOpponents", {}).get(seek["creatorId"], 0)
        weights.append(math.exp(-gap / 150) / (1 + s["repeatPenalty"] * recent))
    i = rng.weighted(weights)
    return {"action": "take", "agentId": eligible[i]["id"], "weight": weights[i], "candidates": len(eligible)}


def answer_challenge(c: dict, m: dict, s: dict, rng: Rng) -> dict:
    """A direct challenge to an agent: accept (after a human delay), decline, or let it sit.
    c: {id, challengerRating, cadence, rated, isPosition}; m: {rating, persona, online, idle}."""
    life = m["persona"]["life"]
    lo = life["answerSeconds"]["min"]
    after_ms = js_round(rng.between(lo, max(lo, life["answerSeconds"]["max"])) * 1000)
    if not m["online"]:
        return {"action": "ignore", "afterMs": 0}
    if not m["idle"]:
        return {"action": "ignore", "afterMs": 0}
    if c["isPosition"] or c["cadence"] not in s["cadences"]:
        return {"action": "decline" if rng.chance(0.5) else "ignore", "afterMs": after_ms}
    if c["cadence"] not in life["cadences"]:
        return {"action": "decline" if rng.chance(0.6) else "ignore", "afterMs": after_ms}
    if abs(c["challengerRating"] - m["rating"]) > life["ratingGap"]:
        return {"action": "decline" if rng.chance(0.5) else "ignore", "afterMs": after_ms}
    return {"action": "accept", "afterMs": after_ms}


def answer_friend_request(p: dict, seed: str) -> dict:
    """A friend request to an agent. Not in the TypeScript kit: people mostly
    accept, the friendlier more often, and not at once - the next time they look
    (between a minute and twenty). Never sent by an agent: agents never start
    contact."""
    rng = rng_from(f"friend/{seed}")
    e = p["etiquette"]
    warmth = (e["greet"] + e["ggWin"] + e["ggLoss"] + e["rematchAccept"]) / 4
    return {
        "accept": rng.chance(min(0.95, 0.55 + 0.5 * warmth)),
        "afterMs": js_round(rng.between(60_000, 20 * 60_000)),
    }


def settings(overrides: Any = None) -> dict:
    """Dispatch settings: the defaults, with a platform's own values on top."""
    s = {**DEFAULT_DISPATCH, "ratingWindow": dict(DEFAULT_RATING_WINDOW)}
    for k, v in (overrides or {}).items():
        if k == "ratingWindow":
            s["ratingWindow"] = {**s["ratingWindow"], **v}
        elif k in s:
            s[k] = v
    if s["waitMaxMs"] < s["waitMinMs"]:
        raise ValueError("waitMaxMs must be at least waitMinMs")
    return s
