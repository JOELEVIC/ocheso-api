"""
Archetypes - starting points for a persona, and the opening lines people play.

Each archetype is a recognisable kind of club player, as trait overrides on top
of "typical for the rating". An agent is created from one and tuned from there;
the persona records which archetype it began as.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.chess.persona import persona
from agents.jsmath import js_round

LINES: dict[str, list[dict]] = json.loads((Path(__file__).parent.parent / "data" / "opening_lines.json").read_text())


def repertoire(groups: list[str]) -> list[dict]:
    """Repertoire entries for a persona from line groups, equal weight."""
    return [{"moves": line["moves"], "weight": 1} for g in groups for line in LINES[g]]


ARCHETYPES: list[dict] = [
    {"id": "typical", "label": "Typical", "description": "Plays like most people at its rating.", "traits": {},
     "white": ["italian"], "blackVsE4": ["blackOpenGame"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "coffeehouse", "label": "Coffeehouse attacker", "description": "Goes for the king, sets traps, plays fast and loves a sacrifice.",
     "traits": {"play": {"strength": {"blunderCheck": 0.3, "middlegame": 40, "endgame": -60},
                         "style": {"aggression": 0.85, "hopeChess": 0.7, "materialism": 0.35, "complication": 0.8, "kingSafety": 0.35, "pawnStorm": 0.7}},
                "clock": {"tempo": 0.7},
                "etiquette": {"greet": 0.6, "resign": 0.3, "niceMove": 0.4, "drawOffer": 0.1, "drawAccept": 0.2}},
     "white": ["italian"], "blackVsE4": ["sicilian"], "blackVsD4": ["blackVsD4Indian"]},
    {"id": "grinder", "label": "Solid grinder", "description": "Trades into endgames it understands and squeezes. Hard to beat, slow to resign.",
     "traits": {"play": {"strength": {"blunderCheck": 0.75, "endgame": 80, "opening": -20}, "style": {"aggression": 0.3, "simplifyWhenAhead": 0.85, "complication": 0.2}},
                "clock": {"tempo": 0.35, "deliberation": 0.7}, "etiquette": {"resign": 0.2, "drawAccept": 0.3}, "temperament": {"tenacity": 0.85}},
     "white": ["london"], "blackVsE4": ["caroKann"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "nervous", "label": "Nervous improver", "description": "Studies hard, plays carefully, rattled by mistakes and by stronger opponents.",
     "traits": {"play": {"strength": {"attention": 0.4, "blunderCheck": 0.6}}, "temperament": {"nerves": 0.85, "tiltSensitivity": 0.8, "recovery": 0.3},
                "clock": {"tempo": 0.4}, "etiquette": {"oops": 0.7, "greet": 0.8, "ggLoss": 0.8}},
     "white": ["italian"], "blackVsE4": ["blackOpenGame"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "timeTrouble", "label": "Time-trouble addict", "description": "Thinks for ages early, then plays the last ten moves on the increment.",
     "traits": {"clock": {"profile": "timeTrouble", "deliberation": 0.9, "tempo": 0.2, "panic": 0.8, "flagRisk": 0.7, "premove": 0.6}},
     "white": ["queensGambit"], "blackVsE4": ["french"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "technician", "label": "Endgame technician", "description": "Weak in the opening, deadly once the queens come off.",
     "traits": {"play": {"strength": {"endgame": 150, "opening": -80}, "style": {"simplifyWhenAhead": 0.8}}, "clock": {"tempo": 0.45}, "temperament": {"tenacity": 0.7}},
     "white": ["london"], "blackVsE4": ["caroKann"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "hopeful", "label": "Hope-chess beginner", "description": "Reaches for the queen early, makes threats and hopes. Plays on to mate.",
     "traits": {"play": {"strength": {"attention": 0.25, "blunderCheck": 0.15}, "style": {"hopeChess": 0.9, "materialism": 0.8, "kingSafety": 0.3}},
                "clock": {"tempo": 0.75, "instantRecapture": 0.8}, "etiquette": {"resign": 0.03, "greet": 0.5}},
     "white": ["beginnerWhite"], "blackVsE4": ["blackOpenGame"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "speed", "label": "Speed demon", "description": "Moves fast, premoves, wins on the clock as often as on the board.",
     "traits": {"play": {"strength": {"blunderCheck": 0.2}},
                "clock": {"tempo": 0.95, "profile": "fastStart", "instantRecapture": 0.95, "premove": 0.9, "deliberation": 0.2, "panic": 0.3},
                "life": {"cadences": ["3+0", "3+2", "5+0"]}},
     "white": ["italian"], "blackVsE4": ["scandinavian"], "blackVsD4": ["blackVsD4Indian"]},
    {"id": "defender", "label": "Stubborn defender", "description": "Never resigns, defends everything, accepts a draw gladly.",
     "traits": {"play": {"style": {"riskWhenBehind": 0.2, "kingSafety": 0.8}}, "etiquette": {"resign": 0.05, "drawAccept": 0.7}, "temperament": {"tenacity": 0.95}},
     "white": ["london"], "blackVsE4": ["french"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "tactician", "label": "Sharp tactician", "description": "Sees combinations others miss; less comfortable in quiet endgames.",
     "traits": {"play": {"strength": {"vision": 0.75, "attention": 0.7, "middlegame": 80, "endgame": -80}, "style": {"aggression": 0.7, "complication": 0.75}}},
     "white": ["italian"], "blackVsE4": ["sicilian"], "blackVsD4": ["blackVsD4Indian"]},
    {"id": "classical", "label": "Solid classical", "description": "Knows its openings, castles early, prefers long games.",
     "traits": {"play": {"strength": {"opening": 60, "blunderCheck": 0.7}, "style": {"kingSafety": 0.8, "aggression": 0.35}}, "clock": {"tempo": 0.3},
                "life": {"cadences": ["10+0", "10+5", "15+10", "30+0"]}},
     "white": ["ruyLopez", "queensGambit"], "blackVsE4": ["blackOpenGame", "caroKann"], "blackVsD4": ["blackVsD4Classical"]},
    {"id": "social", "label": "Friendly regular", "description": "Always greets, always says good game, loves a rematch.",
     "traits": {"form": 0.7, "etiquette": {"greet": 0.95, "ggWin": 0.9, "ggLoss": 0.9, "niceMove": 0.7, "rematchOffer": 0.7, "rematchAccept": 0.85}},
     "white": ["italian"], "blackVsE4": ["blackOpenGame"], "blackVsD4": ["blackVsD4Classical"]},
]


def archetype(archetype_id: str) -> dict:
    for a in ARCHETYPES:
        if a["id"] == archetype_id:
            return a
    raise ValueError(f'no archetype "{archetype_id}"')


def persona_for(archetype_id: str, rating: int) -> dict:
    """A full persona from an archetype at a rating. Below 1000 the repertoire is a beginner's."""
    a = archetype(archetype_id)
    t = a["traits"]
    beginner = rating < 1000
    play = t.get("play", {})
    return persona(
        {
            "archetype": a["id"],
            "rating": rating,
            "form": t.get("form"),
            "clock": t.get("clock"),
            "temperament": t.get("temperament"),
            "etiquette": t.get("etiquette"),
            "life": t.get("life"),
            "play": {
                "strength": play.get("strength"),
                "style": play.get("style"),
                "openings": {
                    "white": repertoire(["beginnerWhite", *a["white"][:1]] if beginner and a["id"] != "classical" else a["white"]),
                    "blackVsE4": repertoire(a["blackVsE4"]),
                    "blackVsD4": repertoire(a["blackVsD4"]),
                    "blackVsOther": repertoire(["blackVsOther"]),
                    "bookDepth": js_round(min(8, 2 + rating / 300)),
                    "misremember": max(0.03, 0.35 - rating / 6000),
                },
            },
        }
    )


def typical_persona(rating: int) -> dict:
    """The "typical person at rating R" the difficulty gauge samples. No repertoire: it thinks from move one."""
    return persona({"archetype": "typical", "rating": rating})
