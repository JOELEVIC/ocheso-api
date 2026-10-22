"""
Mood - what a game and a session do to a person.

Tilt after their own blunder (faster, rasher), confidence when winning
(careless), nerves against a stronger opponent (slower, tighter), fatigue over
a long session, and form: the day's level, drawn once per game. Small numbers
the brain reads; nothing here decides a move.
"""

from __future__ import annotations

from agents.jsmath import clamp
from agents.rng import Rng


def start_game(p: dict, games_this_session: int, opponent_rating: float, rng: Rng) -> dict:
    t = p["temperament"]
    gap = opponent_rating - p["rating"]
    return {
        "tilt": 0,
        "confidence": 0,
        "fatigue": clamp(games_this_session * 0.08 * (0.4 + 1.2 * t["fatigue"]), 0, 1),
        "form": rng.normal() * (40 + 160 * p["form"]),
        "nerves": clamp((gap / 400) * (0.3 + 1.4 * t["nerves"]), 0, 1),
    }


def after_own_move(m: dict, p: dict, loss_pct: float, eval_pct: float) -> dict:
    """`loss_pct`: how much worse the move was than the best (win-% points); `eval_pct`: the position after it."""
    t = p["temperament"]
    tilt = m["tilt"] * (1 - (0.08 + 0.25 * t["recovery"]))
    if loss_pct >= 15:
        tilt += (0.25 + 0.6 * t["tiltSensitivity"]) * clamp(loss_pct / 40, 0.4, 1)
    confidence = clamp((eval_pct - 50) / 30, -1, 1)
    return {**m, "tilt": clamp(tilt, 0, 1), "confidence": confidence}


def after_game(m: dict, p: dict, lost: bool) -> dict:
    """A game ends: tilt carries into the next game of the session, softened."""
    carry = m["tilt"] * (0.3 + 0.4 * p["temperament"]["tiltSensitivity"])
    return {"tilt": clamp(carry + (0.1 * p["temperament"]["tiltSensitivity"] if lost else 0), 0, 1)}
