"""
When an agent is online - a life, not a timer.

Each availability window in the persona's week ("weekday evenings
18:00-22:00") is a chance to turn up. On a given local date the persona does
or doesn't; if it does, it plays one or more sessions of varying length with
gaps between. Drawn from a seed per persona and date, so a preview, a test and
a live decision all agree on whether someone is online at a given minute.
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from agents.jsmath import js_round
from agents.rng import rng_from


def local_time(at: datetime, tz: str) -> dict:
    """The local date, weekday (0 = Sunday) and minute of the day in a time zone."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    local = at.astimezone(ZoneInfo(tz))
    return {
        "date": local.strftime("%Y-%m-%d"),
        "weekday": (local.weekday() + 1) % 7,
        "minute": local.hour * 60 + local.minute,
    }


def _minutes_of(hhmm: str) -> int:
    return int(hhmm[0:2]) * 60 + int(hhmm[3:5])


def _always(w: dict) -> bool:
    """A window of the whole day at full presence: always around, no sessions or breaks.
    Not something the TypeScript kit had; nothing calibrated uses it."""
    return w["presence"] >= 1 and w["from"] == "00:00" and w["to"] in ("23:59", "24:00")


def sessions_on(p: dict, seed: str, date: str, weekday: int) -> list[dict]:
    """The sessions a persona plays on a local date, in minutes after local midnight."""
    out: list[dict] = []
    for i, w in enumerate(p["life"]["weekly"]):
        if weekday not in w["days"]:
            continue
        if _always(w):
            # The whole day, every time: an agent set to be around for testing.
            out.append({"from": 0, "to": 24 * 60})
            continue
        rng = rng_from(f"{seed}/{date}/w{i}")
        if not rng.chance(w["presence"]):
            continue
        start = _minutes_of(w["from"])
        end = _minutes_of(w["to"]) if _minutes_of(w["to"]) > start else 24 * 60
        t = start + rng.between(0, min(40, (end - start) / 3))
        while t < end - 5:
            sm = p["life"]["sessionMinutes"]
            length = max(8, rng.lognormal(sm["median"], sm["spread"]))
            out.append({"from": js_round(t), "to": js_round(min(end, t + length))})
            t += length + rng.lognormal(45, 0.6)
            if not rng.chance(0.55):
                break
    return sorted(out, key=lambda s: s["from"])


def online_at(p: dict, seed: str, at: datetime) -> dict:
    """Is it online at this moment, and until when (minutes after local midnight)?"""
    lt = local_time(at, p["life"]["timeZone"])
    for s in sessions_on(p, seed, lt["date"], lt["weekday"]):
        if s["from"] <= lt["minute"] < s["to"]:
            return {"online": True, "until": s["to"]}
    return {"online": False, "until": None}
