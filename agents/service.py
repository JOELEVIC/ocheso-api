"""
What the API asks of an agent: a move, an answer to a draw offer, a goodbye,
and how hard a position is.

The brain (agents/chess) decides; this keeps a game's continuity between those
decisions - mood, the agent's last move and what it expected in reply, how
long it has been losing - as a small JSON state the session row carries. Each
decision is seeded by the session and ply, so the same request gets the same
answer: retrying a move cannot change it.

It follows CCA's house players, which played real people with the same brain:
greet once the game starts; "oops" when the reply it overlooked arrives;
compliment a strong reply; resign only lost positions, and only if it is the
kind that resigns; offer draws late, level and rarely.
"""

from __future__ import annotations


import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

import chess

from agents.chess.analysis import Analysis, ranked
from agents.chess.archetypes import ARCHETYPES, LINES, persona_for
from agents.chess.board import Position, position_facts
from agents.chess.brain import analyse_position, budget_for
from agents.chess.decide import decide
from agents.chess.gauge import gauge
from agents.chess.persona import CHESS_RATING_RANGE, TRAITS, persona as parse_persona
from agents.chess.priors import PRIORS
from agents.engines import STOCKFISH_VERSION, Engines, Maia, Stockfish
from agents.etiquette import accept_draw, compliment, farewell, greeting, oops, rematch, should_offer_draw, should_resign
from agents.jsmath import js_round
from agents.mood import after_game, after_own_move, start_game
from agents.persona import CLOCK_PROFILES, PersonaError, parse_cadence
from agents.rng import rng_from
from agents.think_time import FIRST_MOVE_CAP_MS

PACES = ("human", "hasty", "instant")


class GameError(ValueError):
    """The request describes a game the agent cannot move in."""


# -----------------------------------------------------------------------------
# Engines: one Stockfish and the Maia sessions per process, made on first use
# -----------------------------------------------------------------------------
_engines: Optional[Engines] = None
_engines_lock = threading.Lock()


def engines() -> Engines:
    global _engines
    with _engines_lock:
        if _engines is None or not _engines.stockfish.alive():
            _engines = Engines(Stockfish(), Maia())
        return _engines


def health() -> dict:
    try:
        e = engines()
        sf = {"ok": True, "name": e.stockfish.name, "matchesCalibration": e.stockfish.matches_calibration}
        maia = [b for b in range(PRIORS.maia_floor, PRIORS.maia_ceiling + 1, 100) if e.maia and e.maia.available(b)]
    except Exception as err:  # noqa: BLE001 - reported, not raised: this is the health check
        sf, maia = {"ok": False, "error": str(err)}, []
    return {"calibration": PRIORS.version, "fittedOn": STOCKFISH_VERSION, "stockfish": sf, "maiaBands": maia}


# -----------------------------------------------------------------------------
# Personas and the library
# -----------------------------------------------------------------------------
def build_persona(*, persona: Optional[dict] = None, archetype: Optional[str] = None,
                  rating: Optional[int] = None) -> dict:
    """A full, strictly parsed persona: as given, or an archetype at a rating."""
    if persona is not None:
        return parse_persona(persona)
    try:
        return persona_for(archetype or "typical", int(rating or 1200))
    except ValueError as err:
        raise PersonaError(str(err)) from err


def library() -> dict:
    return {
        "game": "chess",
        "calibration": PRIORS.version,
        "ratingRange": list(CHESS_RATING_RANGE),
        "archetypes": [{"id": a["id"], "label": a["label"], "description": a["description"],
                        "openings": {"white": a["white"], "blackVsE4": a["blackVsE4"], "blackVsD4": a["blackVsD4"]}}
                       for a in ARCHETYPES],
        "traits": TRAITS,
        "clockProfiles": list(CLOCK_PROFILES),
        "lines": {group: [{"name": line.get("name"), "moves": line["moves"]} for line in lines]
                  for group, lines in LINES.items()},
    }


# -----------------------------------------------------------------------------
# Positions
# -----------------------------------------------------------------------------
@dataclass
class Spot:
    fen: str
    history: list[str]
    prev_fen: Optional[str]
    from_start: bool
    board: chess.Board

    @property
    def plies(self) -> int:
        return len(self.history)


def spot(moves: Optional[list[str]] = None, fen: Optional[str] = None, start_fen: Optional[str] = None) -> Spot:
    """Where the game is: replayed from its moves (best - the agent then knows
    its opening and what was just played), or a bare position."""
    if moves is None and not fen:
        raise GameError("Send the game's moves, or a position (fen).")
    try:
        board = chess.Board(start_fen) if start_fen else chess.Board()
    except ValueError as err:
        raise GameError(f"start_fen is not a position: {err}") from err
    prev = None
    if moves is not None:
        for i, m in enumerate(moves):
            try:
                move = chess.Move.from_uci(m)
            except ValueError:
                raise GameError(f"Move {i + 1} ({m!r}) is not UCI, e.g. e2e4 or e7e8q.") from None
            if move not in board.legal_moves:
                raise GameError(f"Move {i + 1} ({m}) is not legal there.")
            prev = board.fen()
            board.push(move)
        if fen and board.fen().split(" ")[:4] != fen.split(" ")[:4]:
            raise GameError("fen does not match the moves; send one or the other.")
        return Spot(board.fen(), list(moves), prev, start_fen is None, board)
    try:
        board = chess.Board(fen)
    except ValueError as err:
        raise GameError(f"fen is not a position: {err}") from err
    if not board.is_valid():
        raise GameError("That position is not legal.")
    return Spot(board.fen(), [], None, False, board)


def _over(board: chess.Board) -> Optional[str]:
    outcome = board.outcome(claim_draw=False)
    return outcome.termination.name.lower() if outcome else None


# -----------------------------------------------------------------------------
# A move
# -----------------------------------------------------------------------------
def _analyse(rating: int, sp: Spot, clock_ms: float) -> Analysis:
    budget = budget_for(rating)
    # Less time on the clock, a cheaper look: never let thinking flag it.
    budget["movetimeMs"] = js_round(min(1500, max(150, clock_ms / 60)))
    if clock_ms < 15_000:
        budget["deepDepth"] = min(budget["deepDepth"], 6)
    return analyse_position(engines(), sp.fen, sp.history, ratings=[rating], budget=budget)


def _paced(think_ms: float, pace: str) -> int:
    if pace == "instant":
        return 0
    if pace == "hasty":
        return js_round(max(250, think_ms * 0.35))
    return js_round(think_ms)


def _chat(said: Optional[dict], base_ms: int = 0) -> list[dict]:
    return [{"intent": said["intent"], "after_ms": base_ms + said["afterMs"]}] if said else []


def play_move(p: dict, sp: Spot, *, state: dict, seed: str, cadence: str, clock_ms: Optional[float],
              opponent_rating: Optional[int], pace: str = "human") -> tuple[dict, dict]:
    """The agent's move here, and the state to carry to its next one."""
    if _over(sp.board):
        raise GameError(f"The game is over ({_over(sp.board)}).")
    cad = parse_cadence(cadence)
    clock = float(clock_ms) if clock_ms is not None else cad["baseSec"] * 1000.0
    opp = opponent_rating or p["rating"]
    rating = p["rating"]
    st = dict(state or {})
    mood = st.get("mood") or start_game(p, int(st.get("gamesThisSession", 0)), opp, rng_from(f"{seed}/mood"))
    chat: list[dict] = []
    if not st.get("greeted"):
        chat += _chat(greeting(p, rng_from(f"{seed}/greet")))
        st["greeted"] = True

    started = time.monotonic()
    a = _analyse(rating, sp, clock)
    r = ranked(a)
    best_pct = r[0]["pct"] if r else 50

    # What the opponent's last move did - and what it said about ours.
    last = st.get("lastOwn")
    if last and sp.history:
        if last["lossPct"] >= 20 and sp.history[-1] == last.get("expectedReply"):
            chat += _chat(oops(p, last["lossPct"], rng_from(f"{seed}/oops")))
        elif last["lossPct"] < 5 and last["evalPct"] - best_pct >= 12:
            chat += _chat(compliment(p, last["evalPct"] - best_pct, 0.6, rng_from(f"{seed}/nice")))

    # Resign a lost position, if this is someone who resigns.
    lost_streak = int(st.get("lostStreak", 0)) + 1 if best_pct < 12 else 0
    st["lostStreak"] = lost_streak
    if sp.plies >= 2 and should_resign(p, rating, best_pct, lost_streak, rng_from(f"{seed}/resign")):
        wait = js_round(rng_from(f"{seed}/resign-wait").between(2000, 7000))
        st["mood"] = mood
        return {"move": None, "san": None, "resign": True, "offer_draw": False,
                "think_ms": _paced(wait, pace), "chat": chat, "eval_pct": best_pct}, st

    own_move = sp.board.fullmove_number - 1
    d = decide(
        a,
        persona=p,
        priors=PRIORS,
        mood=mood,
        rng=rng_from(seed),
        own_move=own_move,
        clock_ms=clock,
        cadence=cad,
        from_start=sp.from_start,
        prev_fen=sp.prev_fen,
        first_move_cap_ms=FIRST_MOVE_CAP_MS if own_move == 0 else None,
    )
    compute_ms = (time.monotonic() - started) * 1000
    st["mood"] = {**mood, **after_own_move(mood, p, d["lossPct"], d["evalPct"])}
    entry = a.moves.get(d["move"])
    st["lastOwn"] = {"lossPct": d["lossPct"], "evalPct": d["evalPct"], "expectedReply": entry.reply if entry else None}

    after = sp.board.copy()
    after.push(chess.Move.from_uci(d["move"]))
    facts = position_facts(Position(after.fen(), [*sp.history, d["move"]], sp.fen))
    offers = int(st.get("drawOffers", 0))
    offer = should_offer_draw(p, d["evalPct"], facts["phase"], facts["moveNumber"], offers, opp, rng_from(f"{seed}/draw-offer"))
    if offer:
        st["drawOffers"] = offers + 1

    think = _paced(d["thinkMs"], pace)
    return {
        "move": d["move"],
        "san": d["san"],
        "resign": False,
        "offer_draw": offer,
        "think_ms": think,
        # Most of the thinking is the wait; the engines' own time is part of it.
        "wait_ms": max(0, think - js_round(compute_ms)),
        "compute_ms": js_round(compute_ms),
        "chat": chat,
        "eval_pct": round(d["evalPct"], 1),
        "explain": {
            "effective_rating": js_round(d["effectiveRating"]),
            "vision_depth": d["visionDepth"],
            "book": d["book"],
            "loss_pct": round(d["lossPct"], 1),
            "prior_source": d["priorSource"],
            "tags": list(dict.fromkeys(d["tags"])),
            "median_think_ms": js_round(d["medianMs"]),
        },
    }, st


def answer_draw(p: dict, *, state: dict, seed: str, opponent_rating: Optional[int]) -> dict:
    """Accept a draw offer? From its own reading of the position after its last move."""
    mood = (state or {}).get("mood") or {"tilt": 0, "confidence": 0, "fatigue": 0, "form": 0, "nerves": 0}
    eval_pct = ((state or {}).get("lastOwn") or {}).get("evalPct", 50)
    yes = accept_draw(p, eval_pct, opponent_rating or p["rating"], mood, rng_from(f"{seed}/draw-answer"))
    return {"accept": yes, "after_ms": js_round(rng_from(f"{seed}/draw-answer-wait").between(1500, 6000))}


def finish(p: dict, *, state: dict, seed: str, result: str) -> tuple[dict, dict]:
    """The game is over: what it says, whether it wants a rematch, its mood after."""
    mood = (state or {}).get("mood") or {"tilt": 0, "confidence": 0, "fatigue": 0, "form": 0, "nerves": 0}
    st = dict(state or {})
    out: dict[str, Any] = {"chat": [], "rematch": None}
    if result in ("win", "loss", "draw"):
        out["chat"] = _chat(farewell(p, result, mood, rng_from(f"{seed}/farewell")))
        r = rematch(p, result, mood, rng_from(f"{seed}/rematch"))
        out["rematch"] = {"offer": r["offer"], "accept": r["accept"], "after_ms": r["afterMs"]}
        st["mood"] = {**mood, **after_game(mood, p, result == "loss")}
    return out, st


# -----------------------------------------------------------------------------
# Difficulty
# -----------------------------------------------------------------------------
def difficulty(sp: Spot, *, ratings: Optional[list[int]] = None, cadence: str = "10+0",
               clock_ms: Optional[float] = None, samples: int = 100) -> dict:
    """How hard this position is for people, by rating: with a clock (cadence,
    and time left) or, with cadence "untimed", as long as they like."""
    if _over(sp.board):
        raise GameError(f"The game is over there ({_over(sp.board)}).")
    untimed = cadence == "untimed"
    cad = "90+30" if untimed else cadence
    parse_cadence(cad)
    rs = sorted({int(r) for r in (ratings or [400, 800, 1200, 1600, 2000, 2400])})
    a = analyse_position(engines(), sp.fen, sp.history, ratings=rs, budget=budget_for(max(rs)))
    g = gauge(a, ratings=rs, samples=samples, cadence=cad, seed=sp.fen,
              own_move=max(0, sp.board.fullmove_number - 1) or 15, clock_ms=None if untimed else clock_ms)
    g["cadence"] = cadence
    return g


def new_seed() -> str:
    return secrets.token_hex(8)


