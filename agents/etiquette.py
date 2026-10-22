"""
Manners - what an agent says, and when it offers or takes a draw, resigns or
asks for a rematch.

An agent never writes text. What it says is an intent from a short fixed list;
the platform turns intents into its own words, and leaves out any it has no way
to say. Every function returns what to do and how long after the moment, the
way a person reacts a beat later.
"""

from __future__ import annotations

from typing import Optional

from agents.jsmath import clamp, js_round
from agents.rng import Rng

CHAT_INTENTS = ("good-luck", "have-fun", "nice-move", "well-played", "good-game", "thanks", "oops")


def greeting(p: dict, rng: Rng) -> Optional[dict]:
    if not rng.chance(p["etiquette"]["greet"] * 0.9):
        return None
    return {"intent": "good-luck" if rng.chance(0.75) else "have-fun", "afterMs": js_round(rng.between(800, 4500))}


def oops(p: dict, loss_pct: float, rng: Rng) -> Optional[dict]:
    """After its own move turned out badly - said once the opponent shows it."""
    if loss_pct < 20 or not rng.chance(p["etiquette"]["oops"] * 0.8):
        return None
    return {"intent": "oops", "afterMs": js_round(rng.between(600, 3000))}


def compliment(p: dict, opponent_gain_pct: float, criticality: float, rng: Rng) -> Optional[dict]:
    """The opponent found a strong move in a position where it was hard."""
    if opponent_gain_pct < 10 or criticality < 0.5 or not rng.chance(p["etiquette"]["niceMove"] * 0.5):
        return None
    return {"intent": "nice-move", "afterMs": js_round(rng.between(1200, 5000))}


def farewell(p: dict, outcome: str, mood: dict, rng: Rng) -> Optional[dict]:
    e = p["etiquette"]
    if outcome == "win":
        chance = e["ggWin"]
    elif outcome == "draw":
        chance = (e["ggWin"] + e["ggLoss"]) / 2
    else:
        chance = e["ggLoss"] * (1 - 0.5 * mood["tilt"])
    if not rng.chance(chance):
        return None
    if outcome == "loss":
        intent = "well-played" if rng.chance(0.6) else "good-game"
    else:
        intent = "good-game" if rng.chance(0.7) else "thanks"
    return {"intent": intent, "afterMs": js_round(rng.between(1000, 6000))}


def should_resign(p: dict, rating: float, eval_pct: float, lost_streak: int, rng: Rng) -> bool:
    """Whether to resign now, from its own position (win-% for itself) after
    the opponent's move. People below ~800 mostly play on to mate."""
    r = p["etiquette"]["resign"]
    if r <= 0.02:
        return False
    threshold = 1.5 + 9 * r
    if eval_pct > threshold:
        return False
    patience = 1 + js_round(4 * (1 - r) + 2 * p["temperament"]["tenacity"])
    if lost_streak < patience:
        return False
    low_rated_plays_on = clamp((rating - 500) / 700, 0.15, 1)
    return rng.chance(0.5 * low_rated_plays_on)


def should_offer_draw(p: dict, eval_pct: float, phase: float, move_number: int, offers_made: int,
                      opponent_rating: float, rng: Rng) -> bool:
    """Offer a draw: level, simplified, late, and only a couple of times a game."""
    if offers_made >= 2 or move_number < 25 or phase < 0.6:
        return False
    if abs(eval_pct - 50) > 6:
        return False
    vs_stronger = 1.5 if opponent_rating > p["rating"] + 100 else 1
    return rng.chance(0.06 * p["etiquette"]["drawOffer"] * vs_stronger)


def accept_draw(p: dict, eval_pct: float, opponent_rating: float, mood: dict, rng: Rng) -> bool:
    """Answer a draw offer, from its own reading of the position."""
    e = p["etiquette"]
    gap = (opponent_rating - p["rating"]) / 400
    line = 50 + 4 + 14 * e["drawAccept"] + 8 * gap + 6 * mood["tilt"]
    if eval_pct > line:
        return False
    if eval_pct < 35:
        return rng.chance(0.85)
    return rng.chance(0.35 + 0.6 * e["drawAccept"])


def rematch(p: dict, outcome: str, mood: dict, rng: Rng) -> dict:
    """After a game against the same person: offer a rematch? Accept theirs?"""
    e = p["etiquette"]
    revenge = 0.4 * p["temperament"]["revenge"] if outcome == "loss" else 0
    tired = mood["fatigue"] * 0.5
    return {
        "offer": rng.chance(clamp(e["rematchOffer"] + revenge - tired, 0, 0.95)),
        "accept": rng.chance(clamp(e["rematchAccept"] + revenge - tired, 0, 0.98)),
        "afterMs": js_round(rng.between(2500, 9000)),
    }
