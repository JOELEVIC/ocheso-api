"""
Think time - how long this person takes over this move.

One log-normal draw per move. The median is the time a person of this rating
spends per move at this cadence - measured from 5.5 million rated games where
the calibration has a cell, the v0 rule otherwise - bent by the moment: quick
in the opening and on recaptures, longer when the position is critical and
they are the deliberating kind, compressed as the clock runs down. Two hard
limits keep an agent inside the rules people play by: a first move well inside
a platform's opening abort, and no flag unless the persona runs it close.
"""

from __future__ import annotations

import math
from typing import Any, Optional

from agents.curves import trait_factor
from agents.jsmath import clamp, js_round
from agents.rng import Rng

# By default no first move comes later than this after the clocks start:
# inside the 30-second abort many platforms have.
FIRST_MOVE_CAP_MS = 12_000
MIN_MS = 250


def _profile_tilt(profile: str, own_move: int) -> float:
    if profile == "fastStart":
        return 0.6 if own_move < 10 else 1.15
    if profile == "slowStart":
        return 1.6 if own_move < 10 else 0.85
    if profile == "timeTrouble":
        return 1.45 if own_move < 25 else 1
    return 1


def _phase_factor(profile: str, own_move: int) -> float:
    early = 0.35 if own_move < 4 else 0.7 if own_move < 8 else 1.25 if own_move < 25 else 0.95
    return early * _profile_tilt(profile, own_move)


def typical_ms(inp: dict, priors: Any) -> float:
    """The median a person of this rating spends here, before the clock's own pressure."""
    base, inc = inp["cadence"]["baseSec"], inp["cadence"]["incSec"]
    return (base * 1000 * priors.time_usage(inp["rating"])) / priors.expected_moves + inc * 1000 * 0.85


def _move_bucket(own: int) -> str:
    if own < 4:
        return str(own)
    return "4-7" if own < 8 else "8-15" if own < 16 else "16-24" if own < 25 else "25-39" if own < 40 else "40+"


def _clock_bucket(left_sec: float, base_sec: float) -> str:
    f = left_sec / base_sec
    if left_sec < 10:
        return "<10s"
    return "<10%" if f < 0.1 else "<25%" if f < 0.25 else "<50%" if f < 0.5 else ">=50%"


def _cadence_key(cadence: dict) -> str:
    base = cadence["baseSec"] / 60
    return f"{int(base) if base == int(base) else base}+{cadence['incSec']}"


def measured_ms(inp: dict, priors: Any) -> Optional[float]:
    """The measured median for this rating, cadence and move (ms), interpolated
    between rating bands; None where the table has no cell. The first move is
    read from the second: Lichess doesn't charge move one."""
    think = priors.think
    table = think["medianSec"].get(_cadence_key(inp["cadence"])) if think else None
    if not table:
        return None
    bucket = _move_bucket(max(1, inp["ownMove"]))
    bands = sorted(int(b) for b in table if bucket in table[b])
    if not bands:
        return None
    r = inp["rating"]

    def at(b: int) -> float:
        return table[str(b)][bucket] * 1000

    if r <= bands[0]:
        return at(bands[0])
    if r >= bands[-1]:
        return at(bands[-1])
    hi = next(i for i, b in enumerate(bands) if b >= r)
    lo = bands[hi - 1]
    t = (r - lo) / (bands[hi] - lo)
    return math.exp((1 - t) * math.log(at(lo)) + t * math.log(at(bands[hi])))


def think_time(inp: dict, p: dict, mood: dict, priors: Any, rng: Rng) -> dict:
    c = p["clock"]
    tags: list[str] = []
    measured = measured_ms(inp, priors)
    f = priors.think["features"] if priors.think else None
    # Measured: the table already holds the move-number shape for typical
    # players; the persona's clock profile bends it from there.
    if measured is not None:
        median = measured * _profile_tilt(c["profile"], inp["ownMove"])
        tags.append("measured")
        median *= priors.think["clockFactor"].get(_clock_bucket(inp["clockMs"] / 1000, inp["cadence"]["baseSec"]), 1)
    else:
        median = typical_ms(inp, priors) * _phase_factor(c["profile"], inp["ownMove"])
    median *= trait_factor(1 - c["tempo"], 2)
    median *= math.exp(0.9 * (inp["complexity"] - 0.4))
    median *= 1 + (0.3 + 1.7 * c["deliberation"]) * inp["criticality"]

    if inp["book"]:
        median *= 0.25
        tags.append("book")
    if inp["onlyMove"]:
        # People still look at an only move for a while (measured about 0.58x).
        median *= f.get("onlyMove", 0.15) if f else 0.15
        tags.append("only-move")
    elif inp["recapture"]:
        if rng.chance(0.2 + 0.7 * c["instantRecapture"]):
            median *= f.get("recapture", math.nan) * 0.4 if f else 0.12
            tags.append("instant-recapture")
        else:
            median *= f.get("recapture", 0.5) if f else 0.5
    elif inp["inCheck"]:
        median *= f.get("inCheck", 0.7) if f else 0.7

    # Mood: tilt rushes, nerves slow, fatigue rushes, a winning position relaxes.
    median *= 1 - 0.35 * mood["tilt"]
    median *= 1 + 0.35 * mood["nerves"]
    median *= 1 - 0.2 * mood["fatigue"]
    if inp["evalPct"] > 75:
        median *= 1 - 0.3 * p["temperament"]["overconfidence"]

    # The clock: spread what's left over the moves still to come.
    inc_ms = inp["cadence"]["incSec"] * 1000
    moves_left = max(8, priors.expected_moves - inp["ownMove"] * 0.75)
    budget = inp["clockMs"] / moves_left + inc_ms * 0.9
    if median > 1.6 * budget:
        median = 1.6 * budget
        tags.append("clock-pressure")
    trouble = inp["clockMs"] < max(20_000, inp["cadence"]["baseSec"] * 1000 * 0.12)
    if trouble:
        tags.append("time-trouble")

    if trouble and inp["clockMs"] < 10_000 + inc_ms and rng.chance(0.1 + 0.6 * c["premove"]):
        ms = rng.between(120, 450)
        tags.append("premove")
    else:
        sigma = (priors.think["sigma"].get(_cadence_key(inp["cadence"])) if priors.think else None)
        if sigma is None:
            sigma = priors.think_sigma
        ms = rng.lognormal(max(MIN_MS, median), sigma * (0.8 + 0.4 * p["form"]))

    if inp["ownMove"] == 0:
        cap = inp.get("firstMoveCapMs")
        ms = min(ms, (FIRST_MOVE_CAP_MS if cap is None else cap) * rng.between(0.4, 1))
    # Never flag unless this persona runs it close; even then keep a sliver.
    reserve = max(400 if inc_ms > 0 else 800, (1 - c["flagRisk"]) * min(inp["clockMs"] * 0.08, 4000))
    if ms > inp["clockMs"] - reserve:
        ms = max(80, (inp["clockMs"] - reserve) * rng.between(0.25, 0.6))
        tags.append("saving-clock")
    return {
        "medianMs": js_round(median),
        "ms": js_round(clamp(ms, 80, max(80, inp["clockMs"] - 50))),
        "tags": tags,
    }
