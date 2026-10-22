"""
The persona - who an agent is, schema version 2.

Everything that makes one agent play, think, feel and behave differently from
another. The common half (rating, form, clock, temperament, manners, the life
it keeps) is shared by every game; chess's own half lives under `play`
(agents/chess/persona.py).

Almost every trait is a 0-1 slider where 0.5 is "typical for the rating", so a
persona says how this agent differs from others of its strength, and a rating
change alone moves every rating-dependent behaviour with it.

Parsing mirrors the TypeScript schema it was ported from: missing fields take
their defaults, objects fill in what they leave out, and unknown keys are
refused at every level rather than dropped - a stored persona is exactly what
was written. Errors name the path.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

PERSONA_SCHEMA_VERSION = 2


class PersonaError(ValueError):
    pass


Spec = Callable[[Any, str], Any]
MISSING = object()


def _fail(path: str, why: str):
    raise PersonaError(f"{path or 'persona'}: {why}")


def number(lo: float, hi: float, default: Any = MISSING, integer: bool = False) -> Spec:
    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            if default is MISSING:
                _fail(path, "is required")
            return default
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            _fail(path, "must be a number")
        if integer and float(v) != int(v):
            _fail(path, "must be a whole number")
        if not lo <= v <= hi:
            _fail(path, f"must be between {lo} and {hi}")
        return int(v) if integer else v

    return parse


def unit(default: float = 0.5) -> Spec:
    return number(0, 1, default)


def string(default: Any = MISSING, pattern: str | None = None, min_len: int = 0, max_len: int = 10_000, why: str = "") -> Spec:
    rx = re.compile(pattern) if pattern else None

    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            if default is MISSING:
                _fail(path, "is required")
            return default
        if not isinstance(v, str):
            _fail(path, "must be text")
        if not min_len <= len(v) <= max_len:
            _fail(path, f"must be {min_len} to {max_len} characters")
        if rx and not rx.search(v):
            _fail(path, why or f"must match {pattern}")
        return v

    return parse


def literal(value: Any) -> Spec:
    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            return value
        if v != value:
            _fail(path, f"must be {value!r}")
        return v

    return parse


def enum(options: tuple[str, ...], default: Any = MISSING) -> Spec:
    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            if default is MISSING:
                _fail(path, "is required")
            return default
        if v not in options:
            _fail(path, f"must be one of {', '.join(options)}")
        return v

    return parse


def array(item: Spec, default: Any = MISSING, min_len: int = 0, max_len: int = 10_000) -> Spec:
    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            if default is MISSING:
                _fail(path, "is required")
            return json.loads(json.dumps(default))
        if not isinstance(v, list):
            _fail(path, "must be a list")
        if not min_len <= len(v) <= max_len:
            _fail(path, f"must have {min_len} to {max_len} items")
        return [item(x, f"{path}[{i}]") for i, x in enumerate(v)]

    return parse


def obj(fields: dict[str, Spec], prefault: Any = MISSING) -> Spec:
    """A strict object. With `prefault`, a missing value parses as that value."""

    def parse(v: Any, path: str):
        if v is None or v is MISSING:
            if prefault is MISSING:
                _fail(path, "is required")
            v = prefault
        if not isinstance(v, dict):
            _fail(path, "must be an object")
        unknown = [k for k in v if k not in fields]
        if unknown:
            _fail(path, f"unknown field{'s' if len(unknown) > 1 else ''}: {', '.join(unknown)}")
        out = {}
        for key, spec in fields.items():
            out[key] = spec(v.get(key, MISSING), f"{path}.{key}" if path else key)
        return out

    return parse


# -----------------------------------------------------------------------------
# The common half
# -----------------------------------------------------------------------------
CADENCE = string(pattern=r"^\d{1,3}\+\d{1,3}$", why="base minutes + increment seconds, e.g. 10+5")
HHMM = string(pattern=r"^([01]\d|2[0-3]):[0-5]\d$", why="use HH:MM")
CLOCK_PROFILES = ("even", "fastStart", "slowStart", "timeTrouble")


def parse_cadence(c: str) -> dict:
    m = re.match(r"^(\d+)\+(\d+)$", c)
    if not m:
        raise ValueError(f"not a cadence: {c}")
    return {"baseSec": int(m.group(1)) * 60, "incSec": int(m.group(2))}


CLOCK = obj(
    {
        "tempo": unit(),
        "profile": enum(CLOCK_PROFILES, "even"),
        "deliberation": unit(),
        "instantRecapture": unit(),
        "premove": unit(),
        "panic": unit(),
        "flagRisk": unit(0.3),
    },
    prefault={},
)

TEMPERAMENT = obj(
    {k: unit() for k in ("tiltSensitivity", "recovery", "overconfidence", "nerves", "fatigue", "revenge", "tenacity")},
    prefault={},
)

ETIQUETTE = obj(
    {
        "greet": unit(),
        "ggWin": unit(),
        "ggLoss": unit(),
        "oops": unit(0.3),
        "niceMove": unit(0.3),
        "drawOffer": unit(0.3),
        "drawAccept": unit(),
        "resign": unit(),
        "rematchOffer": unit(0.3),
        "rematchAccept": unit(),
    },
    prefault={},
)

AVAILABILITY = obj(
    {
        "days": array(number(0, 6, integer=True), min_len=1),
        "from": HHMM,
        "to": HHMM,
        "presence": unit(0.6),
    }
)

LIFE = obj(
    {
        "timeZone": string("Africa/Douala", min_len=1, max_len=64),
        "weekly": array(AVAILABILITY, [{"days": [1, 2, 3, 4, 5], "from": "18:00", "to": "22:00", "presence": 0.6}], max_len=14),
        "sessionMinutes": obj({"median": number(5, 600), "spread": number(0, 2)}, prefault={"median": 45, "spread": 0.5}),
        "breakMinutes": obj({"median": number(0, 120), "spread": number(0, 2)}, prefault={"median": 3, "spread": 0.6}),
        "cadences": array(CADENCE, ["5+0", "10+0"], min_len=1, max_len=40),
        "ratingGap": number(0, 2000, 400, integer=True),
        "answerSeconds": obj({"min": number(1, 120), "max": number(1, 300)}, prefault={"min": 4, "max": 20}),
    },
    prefault={},
)


def persona_schema(game: str, play: Spec, rating: tuple[int, int]) -> Spec:
    return obj(
        {
            "game": literal(game),
            "schemaVersion": literal(PERSONA_SCHEMA_VERSION),
            "archetype": string("custom", min_len=1, max_len=40),
            "rating": number(rating[0], rating[1], integer=True),
            "form": unit(),
            "clock": CLOCK,
            "temperament": TEMPERAMENT,
            "etiquette": ETIQUETTE,
            "life": LIFE,
            "notes": string("", max_len=2000),
            "play": play,
        }
    )


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace: one text per persona, so a version's hash names its content."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


COMMON_TRAITS: dict[str, dict] = {
    "form": {"label": "Form swings", "low": "plays the same level every game", "high": "brilliant one day, poor the next"},
    "clock.tempo": {"label": "Speed", "low": "slow and careful", "high": "fast"},
    "clock.deliberation": {"label": "Deliberation", "low": "same pace everywhere", "high": "stops to think at critical moments"},
    "clock.instantRecapture": {"label": "Instant recaptures", "low": "thinks before recapturing", "high": "recaptures at once"},
    "clock.premove": {"label": "Premoves", "low": "never premoves", "high": "premoves in time trouble"},
    "clock.panic": {"label": "Panic", "low": "calm with little time", "high": "falls apart in time trouble"},
    "clock.flagRisk": {"label": "Flag risk", "low": "keeps time in hand", "high": "runs the clock close to zero"},
    "temperament.tiltSensitivity": {"label": "Tilt", "low": "shrugs off mistakes", "high": "a blunder rattles it"},
    "temperament.recovery": {"label": "Recovery", "low": "stays rattled", "high": "settles quickly"},
    "temperament.overconfidence": {"label": "Overconfidence", "low": "careful when winning", "high": "relaxes when winning"},
    "temperament.nerves": {"label": "Nerves", "low": "unbothered by strong opponents", "high": "tense against stronger players"},
    "temperament.fatigue": {"label": "Fatigue", "low": "fresh all session", "high": "tires over a long session"},
    "temperament.revenge": {"label": "Revenge", "low": "takes a loss calmly", "high": "wants a rematch after losing"},
    "temperament.tenacity": {"label": "Tenacity", "low": "collapses when worse", "high": "defends for ever"},
    "etiquette.greet": {"label": "Greets", "low": "never says hello", "high": "always wishes good luck"},
    "etiquette.ggWin": {"label": "GG after a win", "low": "silent", "high": "always"},
    "etiquette.ggLoss": {"label": "GG after a loss", "low": "leaves without a word", "high": "always"},
    "etiquette.oops": {"label": "Says oops", "low": "never", "high": "after every slip"},
    "etiquette.niceMove": {"label": "Compliments", "low": "never", "high": "praises good moves"},
    "etiquette.drawOffer": {"label": "Offers draws", "low": "never", "high": "in any level position"},
    "etiquette.drawAccept": {"label": "Accepts draws", "low": "plays on", "high": "takes the half point"},
    "etiquette.resign": {"label": "Resigns", "low": "plays on to mate", "high": "resigns once it's lost"},
    "etiquette.rematchOffer": {"label": "Offers rematches", "low": "never", "high": "usually"},
    "etiquette.rematchAccept": {"label": "Accepts rematches", "low": "rarely", "high": "almost always"},
}
