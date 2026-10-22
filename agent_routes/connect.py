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
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Header, HTTPException, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from agents import dispatch, schedule, service
from agents.rng import rng_from
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
    # Your own game id. Opening again with the same one returns the live
    # session it already has (after a restart on your side), mood and all.
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
            "agent": {k: opened["agent"][k] for k in ("id", "name", "game", "rating")},
            # True when this game already had a live session (same external_ref): it carries on.
            "resumed": bool(opened.get("resumed"))}


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


# -----------------------------------------------------------------------------
# A platform's people around the agents: who is online, seats, challenges,
# friend requests. The agents' lives (agents/schedule.py) and the rules that
# keep people first (agents/dispatch.py) decide here; the platform gathers the
# facts and acts. Agents never start contact: there is no route for an agent
# to challenge or befriend anyone.
# -----------------------------------------------------------------------------
class SeekIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=120)
    creator_id: str = Field(min_length=1, max_length=120)
    creator_rating: int = Field(ge=0, le=3500)
    cadence: str = Field(pattern=r"^\d{1,3}\+\d{1,3}$")
    created_at_ms: int = Field(ge=0)
    heartbeat_at_ms: int = Field(ge=0)
    is_position: bool = False
    # Other people's open seeks this one could still be paired with, by the
    # platform's own pairing rules: while there are any, no agent steps in.
    human_alternatives: int = Field(0, ge=0)


class SeatAgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    idle: bool
    # Games against each person in the last week, so the same agent rarely meets them twice running.
    recent_opponents: dict[str, int] = Field(default_factory=dict)


class DispatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wait_min_ms: Optional[int] = Field(None, ge=3_000, le=40_000)
    wait_max_ms: Optional[int] = Field(None, ge=3_000, le=44_000)
    max_heartbeat_age_ms: Optional[int] = Field(None, ge=5_000, le=60_000)
    repeat_penalty: Optional[float] = Field(None, ge=0, le=20)
    cadences: Optional[list[str]] = Field(None, max_length=40)
    # The platform's own pairing window, so an agent is never a closer match than a person would have been.
    rating_window: Optional[dict[str, int]] = None

    def to_settings(self) -> dict:
        names = {"wait_min_ms": "waitMinMs", "wait_max_ms": "waitMaxMs", "max_heartbeat_age_ms": "maxHeartbeatAgeMs",
                 "repeat_penalty": "repeatPenalty", "cadences": "cadences", "rating_window": "ratingWindow"}
        out = {}
        for k, v in self.model_dump(exclude_none=True).items():
            if k == "rating_window":
                v = {{"start": "start", "step": "step", "step_ms": "stepMs", "anyone_after_ms": "anyoneAfterMs"}.get(a, a): b
                     for a, b in v.items()}
            out[names[k]] = v
        return out


class SeatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seek: SeekIn
    agents: list[SeatAgentIn] = Field(max_length=200)
    settings: Optional[DispatchIn] = None
    # The schedule is the agent's life; a platform testing its integration may set it aside.
    ignore_schedule: bool = False


class ChallengeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=1, max_length=120)
    challenger_rating: int = Field(ge=0, le=3500)
    cadence: str = Field(pattern=r"^\d{1,3}\+\d{1,3}$")
    rated: bool = True
    is_position: bool = False
    # Whether the agent is free right now (no game in progress) - the platform knows.
    idle: bool = True
    settings: Optional[DispatchIn] = None
    ignore_schedule: bool = False


class FriendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=120)


def roster(key: str) -> dict[str, dict]:
    """The key's agents, with personas, as the API's own working copy."""
    got = call("agent-key", "agent_machine_key", {"key": key, "personas": True})
    return {a["id"]: a for a in got["agents"]}


def dispatch_settings(s: Optional[DispatchIn]) -> dict:
    try:
        return dispatch.settings(s.to_settings() if s else None)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None


def presence_of(agent: dict, at: datetime, ignore_schedule: bool = False) -> dict:
    """Online now: active, and inside a session of its week (or the schedule set aside)."""
    if agent["status"] != "active":
        return {"online": False, "until": None}
    if ignore_schedule:
        return {"online": True, "until": None}
    p = persona_of(agent)
    now = schedule.online_at(p, agent["id"], at)
    if not now["online"]:
        return {"online": False, "until": None}
    local = schedule.local_time(at, p["life"]["timeZone"])
    left = now["until"] - local["minute"]
    return {"online": True, "until": (at + timedelta(minutes=left)).isoformat()}


def next_online(agent: dict, at: datetime, days: int = 7) -> Optional[str]:
    """When its next session starts, within a week."""
    if agent["status"] != "active":
        return None
    p = persona_of(agent)
    tz = ZoneInfo(p["life"]["timeZone"])
    local_now = at.astimezone(tz)
    for d in range(days + 1):
        day = (local_now + timedelta(days=d)).date()
        weekday = (day.weekday() + 1) % 7
        for s in schedule.sessions_on(p, agent["id"], day.isoformat(), weekday):
            start = datetime(day.year, day.month, day.day, tzinfo=tz) + timedelta(minutes=s["from"])
            if start > local_now:
                return start.astimezone(timezone.utc).isoformat()
    return None


@router.get("/presence", summary="Which agents are online now, and until when")
def presence(at: Optional[datetime] = None, ignore_schedule: bool = False,
             authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    agents = roster(key_hash(authorization, x_ocheso_key))
    out = []
    for a in agents.values():
        p = persona_of(a)
        here = presence_of(a, now, ignore_schedule)
        out.append({"id": a["id"], "name": a["name"], "rating": a["rating"], "status": a["status"],
                    "cadences": p["life"]["cadences"], "online": here["online"], "until": here["until"],
                    "next_online": None if here["online"] else next_online(a, now)})
    return {"at": now.isoformat(), "agents": out}


@router.post("/seat", summary="A person is waiting for a game: should an agent take the seat, and which?")
def seat(body: SeatIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    now = datetime.now(timezone.utc)
    agents = roster(key_hash(authorization, x_ocheso_key))
    views = []
    for a in body.agents:
        agent = agents.get(a.id)
        if agent is None:
            continue
        views.append({"id": a.id, "rating": agent["rating"], "persona": persona_of(agent), "idle": a.idle,
                      "online": presence_of(agent, now, body.ignore_schedule)["online"],
                      "recentOpponents": a.recent_opponents})
    s = body.seek
    seek = {"id": s.id, "creatorId": s.creator_id, "creatorRating": s.creator_rating, "cadence": s.cadence,
            "createdAtMs": s.created_at_ms, "heartbeatAtMs": s.heartbeat_at_ms, "isPosition": s.is_position,
            "humanAlternatives": s.human_alternatives}
    d = dispatch.decide_seat(seek, views, now.timestamp() * 1000, dispatch_settings(body.settings),
                             rng_from(f"seat/{s.id}/{int(now.timestamp() // 5)}"))
    out = {"action": d["action"], "reason": d.get("reason")}
    if d["action"] == "take":
        out.update({"agent": d["agentId"], "candidates": d["candidates"]})
    if d["action"] == "wait":
        out["retry_in_ms"] = int(d["retryInMs"])
    return out


@router.post("/agents/{agent_id}/challenge", summary="A person challenges an agent: accept, decline or let it sit")
def challenge(agent_id: str, body: ChallengeIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    agent = roster(key_hash(authorization, x_ocheso_key)).get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="This key cannot use that agent.")
    now = datetime.now(timezone.utc)
    m = {"id": agent_id, "rating": agent["rating"], "persona": persona_of(agent), "idle": body.idle,
         "online": presence_of(agent, now, body.ignore_schedule)["online"], "recentOpponents": {}}
    c = {"id": body.challenge_id, "challengerRating": body.challenger_rating, "cadence": body.cadence,
         "rated": body.rated, "isPosition": body.is_position}
    a = dispatch.answer_challenge(c, m, dispatch_settings(body.settings), rng_from(f"challenge/{body.challenge_id}"))
    return {"action": a["action"], "after_ms": a["afterMs"], "online": m["online"]}


@router.post("/agents/{agent_id}/friend-request", summary="A person asks an agent to be friends: accept, and when")
def friend_request(agent_id: str, body: FriendIn, authorization: KeyHeader = None, x_ocheso_key: AltKeyHeader = None):
    agent = roster(key_hash(authorization, x_ocheso_key)).get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="This key cannot use that agent.")
    a = dispatch.answer_friend_request(persona_of(agent), f"{agent_id}/{body.request_id}")
    return {"accept": a["accept"], "after_ms": a["afterMs"]}
