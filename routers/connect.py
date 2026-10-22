"""
Agents, for platforms: the routes an integration key (`och_...`) opens.

A platform seats an agent in a game on its own servers and asks it for moves.
Two ways to get them:

  * sync - POST a move request; the answer carries the move and `think_ms`,
    how long a person would take. Play it then (or send `wait: true` and the
    answer arrives when it is due, up to a minute).
  * realtime - open the session with `realtime: true`, subscribe to the
    Supabase Realtime channel it returns, and POST move requests; the answer
    is 202 at once, and the move is broadcast on the channel when a person
    would have played it. Each payload is {data, sig}: `sig` is HMAC-SHA256
    of `data`'s canonical JSON (sorted keys, no spaces) under the session's
    secret. Check it - anyone who learnt the channel name could post to it.

The key never reaches the database. Its SHA-256 does, inside a request this
API signs (play/referee.py), and db/agents.sql decides whether that key may
drive that agent - and refuses a paused one, mid-game or not.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Header, HTTPException, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from agents import service
from agents.persona import PersonaError
from config import settings
from db import anon_db, one
from play.referee import sign_request

router = APIRouter(prefix="/v1/connect", tags=["Agents for platforms"])

KEY = re.compile(r"^och_[0-9a-f]{48}$")
MAX_WAIT_MS = 60_000


class OpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: str
    color: Optional[Literal["white", "black"]] = None
    cadence: str = Field("10+0", pattern=r"^\d{1,3}\+\d{1,3}$")
    opponent_rating: Optional[int] = Field(None, ge=100, le=3500)
    realtime: bool = False
    # Your own game id, so you can find the session again.
    external_ref: Optional[str] = Field(None, max_length=120)
    # Games this agent already played in this sitting: it tires.
    games_this_session: int = Field(0, ge=0, le=50)


class MoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The game so far, in UCI from the start (or from start_fen). Or just a fen.
    moves: Optional[list[str]] = Field(None, max_length=600)
    fen: Optional[str] = Field(None, max_length=100)
    start_fen: Optional[str] = Field(None, max_length=100)
    # The agent's time left, and the cadence if there is no session.
    clock_ms: Optional[int] = Field(None, ge=0, le=36_000_000)
    pace: Literal["human", "hasty", "instant"] = "human"
    wait: bool = False


class OneOffIn(MoveIn):
    cadence: str = Field("10+0", pattern=r"^\d{1,3}\+\d{1,3}$")
    opponent_rating: Optional[int] = Field(None, ge=100, le=3500)


class EndIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # From the agent's side.
    result: Literal["win", "loss", "draw", "aborted"]


class DifficultyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    moves: Optional[list[str]] = Field(None, max_length=600)
    fen: Optional[str] = Field(None, max_length=100)
    start_fen: Optional[str] = Field(None, max_length=100)
    ratings: Optional[list[int]] = Field(None, min_length=1, max_length=13)
    cadence: str = Field("10+0", pattern=r"^(\d{1,3}\+\d{1,3}|untimed)$")
    clock_ms: Optional[int] = Field(None, ge=0, le=36_000_000)
    samples: int = Field(100, ge=10, le=300)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def key_hash(authorization: Optional[str], x_ocheso_key: Optional[str]) -> str:
    raw = x_ocheso_key or ""
    if not raw and authorization:
        scheme, _, token = authorization.partition(" ")
        raw = token if scheme.lower() == "bearer" else ""
    if not KEY.match(raw):
        raise HTTPException(status_code=401, detail="Send your agent key: Authorization: Bearer och_...")
    return hashlib.sha256(raw.encode()).hexdigest()


KeyHeader = Annotated[Optional[str], Header(alias="Authorization")]
AltKeyHeader = Annotated[Optional[str], Header(alias="X-Ocheso-Key")]


def call(kind: str, fn: str, body: dict) -> dict:
    # As anon: a platform has no account. The signature is what lets it in.
    payload, sig = sign_request(kind, body)
    return one(anon_db().rpc(fn, {"p_payload": payload, "p_sig": sig}).execute())


async def acall(kind: str, fn: str, body: dict) -> dict:
    return await run_in_threadpool(call, kind, fn, body)


def persona_of(agent: dict) -> dict:
    try:
        return service.build_persona(persona=agent["persona"])
    except PersonaError as err:
        raise HTTPException(status_code=409, detail=f"That agent's persona no longer parses: {err}") from None


def spot_of(body) -> service.Spot:
    try:
        return service.spot(body.moves, body.fen, body.start_fen)
    except service.GameError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None


def session_out(s: dict) -> dict:
    out = {
        "id": s["id"], "agent": s["agent"], "external_ref": s.get("externalRef"), "color": s.get("color"),
        "cadence": s["cadence"], "opponent_rating": s.get("opponentRating"), "plies": s.get("plies", 0),
        "status": s["status"], "result": s.get("result"), "started_at": s.get("startedAt"),
    }
    if s.get("realtime"):
        out["realtime"] = {
            "url": settings.SUPABASE_URL,
            "key": settings.SUPABASE_ANON_KEY,
            "topic": f"agent:{s['channel']}",
            "events": ["move", "end"],
            "secret": s["secret"],
        }
    return out


def signed_payload(secret: str, body: dict) -> dict:
    """{data, sig}: Realtime adds its own fields beside ours (an `id`), so the
    signed part travels as one object, HMAC-SHA256 over its canonical JSON."""
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return {"data": body, "sig": hmac.new(secret.encode(), text.encode(), hashlib.sha256).hexdigest()}


async def decide_off_loop(fn, *args, **kwargs):
    # The engines block; keep the event loop free for other requests.
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except service.GameError as err:
        raise HTTPException(status_code=409, detail=str(err)) from None
    except (RuntimeError, OSError) as err:
        if isinstance(err, OSError) or "Stockfish" in str(err):
            raise HTTPException(status_code=503, detail="The agents' engines aren't available right now.") from None
        raise


def stamp(out: dict, started: float) -> dict:
    """When to play it: the think time, counted from when the request arrived."""
    out["play_at"] = int(started * 1000 + out["think_ms"])
    return out


async def deliver(out: dict, wait: bool) -> dict:
    if wait:
        await asyncio.sleep(min(MAX_WAIT_MS, max(0, out["play_at"] - time.time() * 1000)) / 1000)
    return out


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@router.get("/agents", summary="The agents this key can use")
def key_agents(authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    found = call("agent-key", "agent_machine_key", {"key": key_hash(authorization, x_ocheso_key)})
    return found["agents"]


@router.post("/agents/{agent_id}/move", summary="One move, no session: the agent as it is")
async def one_off_move(agent_id: str, body: OneOffIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    started = time.time()
    key = key_hash(authorization, x_ocheso_key)
    sp = spot_of(body)
    agent = await acall("agent-use", "agent_machine_use", {"key": key, "agent": agent_id})
    p = persona_of(agent)
    out, _ = await decide_off_loop(service.play_move, p, sp, state={"greeted": True}, seed=service.new_seed(),
                                   cadence=body.cadence, clock_ms=body.clock_ms,
                                   opponent_rating=body.opponent_rating, pace=body.pace)
    return await deliver(stamp({"agent": agent["id"], **out}, started), body.wait)


@router.post("/sessions", status_code=201, summary="Seat an agent in a game")
def open_session(body: OpenIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    opened = call("agent-open", "agent_machine_open", {
        "key": key_hash(authorization, x_ocheso_key), "agent": body.agent, "color": body.color,
        "cadence": body.cadence, "opponentRating": body.opponent_rating, "realtime": body.realtime,
        "externalRef": body.external_ref, "state": {"gamesThisSession": body.games_this_session},
    })
    return {"session": session_out(opened["session"]),
            "agent": {k: opened["agent"][k] for k in ("id", "name", "game", "rating")}}


@router.post("/sessions/{session_id}/move", summary="The agent's move")
async def session_move(session_id: str, body: MoveIn, response: Response,
                       authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    started = time.time()
    key = key_hash(authorization, x_ocheso_key)
    sp = spot_of(body)
    got = await acall("agent-session", "agent_machine_session", {"key": key, "session": session_id})
    s, agent = got["session"], got["agent"]
    if s["status"] != "live":
        raise HTTPException(status_code=409, detail="That session has ended.")
    p = persona_of(agent)
    if s.get("color") and ("white" if sp.board.turn else "black") != s["color"]:
        raise HTTPException(status_code=409, detail=f"It isn't the agent's move: it plays {s['color']}.")
    # A retry of the last request gets the same answer; an older position is
    # refused rather than given a second move for a turn already played.
    last = (s.get("state") or {}).get("last")
    if last and sp.plies == last["ply"] and sp.fen == last["fen"]:
        if s.get("realtime") and not body.wait:
            response.status_code = 202
            return {"session": s["id"], "ply": sp.plies, "play_at": last["out"]["play_at"], "delivery": "realtime"}
        return await deliver(dict(last["out"]), body.wait)
    if last and sp.plies <= last["ply"]:
        raise HTTPException(status_code=409, detail="The agent has already moved past that position.")
    seed = f"{s['id']}/{sp.plies}/{sp.fen}"
    out, state = await decide_off_loop(service.play_move, p, sp, state=s["state"], seed=seed, cadence=s["cadence"],
                                       clock_ms=body.clock_ms, opponent_rating=s.get("opponentRating"), pace=body.pace)
    out = stamp({"session": s["id"], "ply": sp.plies, **out}, started)
    state["last"] = {"ply": sp.plies, "fen": sp.fen, "out": out}
    record = {"key": key, "session": s["id"], "plies": s["plies"], "state": state}
    if s.get("realtime"):
        public = {k: out[k] for k in ("session", "ply", "move", "san", "resign", "offer_draw", "think_ms", "play_at", "chat")}
        record["deliver"] = {"event": "move", "payload": signed_payload(s["secret"], public), "at": out["play_at"]}
    await acall("agent-record", "agent_machine_record", record)
    if s.get("realtime") and not body.wait:
        response.status_code = 202
        return {"session": s["id"], "ply": sp.plies, "play_at": out["play_at"], "delivery": "realtime"}
    return await deliver(out, body.wait)


@router.post("/sessions/{session_id}/draw", summary="The opponent offers a draw: does the agent accept?")
def session_draw(session_id: str, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    got = call("agent-session", "agent_machine_session", {"key": key_hash(authorization, x_ocheso_key), "session": session_id})
    s = got["session"]
    if s["status"] != "live":
        raise HTTPException(status_code=409, detail="That session has ended.")
    return service.answer_draw(persona_of(got["agent"]), state=s["state"], seed=f"{s['id']}/draw/{s['plies']}",
                               opponent_rating=s.get("opponentRating"))


@router.post("/sessions/{session_id}/end", summary="The game is over")
def session_end(session_id: str, body: EndIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    key = key_hash(authorization, x_ocheso_key)
    # Read even if the agent was paused since: a game can always be ended.
    got = call("agent-session", "agent_machine_session", {"key": key, "session": session_id, "ending": True})
    s = got["session"]
    said, state = service.finish(persona_of(got["agent"]), state=s["state"], seed=f"{s['id']}/end", result=body.result)
    record = {"key": key, "session": s["id"], "result": body.result, "state": state}
    if s.get("realtime") and s["status"] == "live":
        record["deliver"] = {"event": "end", "payload": signed_payload(s["secret"], {"session": s["id"], **said}),
                             "at": int(time.time() * 1000)}
    ended = call("agent-end", "agent_machine_end", record)
    return {"session": session_out({**ended, "realtime": False}), **said}


@router.post("/difficulty", summary="How hard a position is for people, by rating, with or without a clock")
async def key_difficulty(body: DifficultyIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    key = key_hash(authorization, x_ocheso_key)
    sp = spot_of(body)
    await acall("agent-key", "agent_machine_key", {"key": key, "gauge": True})
    return await decide_off_loop(service.difficulty, sp, ratings=body.ratings, cadence=body.cadence,
                                 clock_ms=body.clock_ms, samples=body.samples)
