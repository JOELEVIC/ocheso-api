"""
Agents, for their owner: the library to hire from, building and tuning,
copies, keys for platforms, a playground, usage.

Ownership is the database's business (db/agents.sql): every query runs as the
signed-in caller and RLS shows them their own agents only. What this module
adds is the persona check - strict, every field named (agents/persona.py) -
and a signature on what passed it, which is the only way a persona reaches
the table.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Annotated, Any, Literal, Optional

import chess
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from agents import service
from agents.persona import PersonaError
from db import UserDb, one, rows
from play.referee import caller_id, sign

router = APIRouter(tags=["Agents"])

Auth = Annotated[Optional[str], Header(alias="Authorization")]

AGENT_COLUMNS = "id,name,game,archetype,parent_id,persona,rating,status,notes,created_at,updated_at"
KEY_COLUMNS = "id,name,prefix,agent_ids,created_at,last_used_at,revoked_at"


class AgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=40)
    # From the library at a rating, or a whole persona from the builder.
    archetype: Optional[str] = Field(None, max_length=40)
    rating: Optional[int] = Field(None, ge=100, le=2600)
    persona: Optional[dict[str, Any]] = None
    notes: str = Field("", max_length=2000)
    status: Literal["draft", "active"] = "draft"


class AgentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(None, min_length=2, max_length=40)
    notes: Optional[str] = Field(None, max_length=2000)
    status: Optional[Literal["draft", "active", "paused"]] = None
    persona: Optional[dict[str, Any]] = None


class CopyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(None, min_length=2, max_length=40)
    rating: Optional[int] = Field(None, ge=100, le=2600)


class KeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    # Which agents it may drive; leave out for all of yours.
    agents: Optional[list[str]] = Field(None, min_length=1, max_length=50)


class KeyPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)


class PositionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    moves: Optional[list[str]] = Field(None, max_length=600)
    fen: Optional[str] = Field(None, max_length=100)
    start_fen: Optional[str] = Field(None, max_length=100)


class TryIn(PositionIn):
    cadence: str = Field("10+0", pattern=r"^\d{1,3}\+\d{1,3}$")
    clock_ms: Optional[int] = Field(None, ge=0, le=36_000_000)
    opponent_rating: Optional[int] = Field(None, ge=100, le=3500)
    # The same position decided this many times, as a person would on different days.
    samples: int = Field(12, ge=1, le=40)


class DifficultyIn(PositionIn):
    ratings: Optional[list[int]] = Field(None, min_length=1, max_length=13)
    cadence: str = Field("10+0", pattern=r"^(\d{1,3}\+\d{1,3}|untimed)$")
    clock_ms: Optional[int] = Field(None, ge=0, le=36_000_000)
    samples: int = Field(100, ge=10, le=300)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def persona_or_422(**kw) -> dict:
    try:
        return service.build_persona(**kw)
    except PersonaError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None


def save(db, by: str, body: dict) -> dict:
    payload, sig = sign("agent-save", by, body)
    return one(db.rpc("save_agent", {"p_payload": payload, "p_sig": sig}).execute())


def mine(db, agent_id: str) -> dict:
    return one(db.table("agents").select(AGENT_COLUMNS).eq("id", agent_id).execute(), missing="No such agent.")


def spot_or_422(body: PositionIn) -> service.Spot:
    try:
        return service.spot(body.moves, body.fen, body.start_fen)
    except service.GameError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None


def engines_or_503():
    try:
        service.engines()
    except Exception:
        raise HTTPException(status_code=503, detail="The agents' engines aren't available right now.") from None


# -----------------------------------------------------------------------------
# The library
# -----------------------------------------------------------------------------
@router.get("/v1/agents/library", summary="Archetypes to hire, the traits a persona has, opening lines")
def get_library():
    return service.library()


@router.get("/v1/agents/library/{archetype}", summary="An archetype's persona at a rating")
def library_persona(archetype: str, rating: int = 1200):
    if not 100 <= rating <= 2600:
        raise HTTPException(status_code=422, detail="rating must be between 100 and 2600")
    return persona_or_422(archetype=archetype, rating=rating)


@router.post("/v1/agents/position", summary="A position: its FEN, legal moves and the moves so far in SAN")
def position(body: PositionIn):
    sp = spot_or_422(body)
    replay = chess.Board(body.start_fen) if body.start_fen else chess.Board()
    san = []
    for m in sp.history:
        move = chess.Move.from_uci(m)
        san.append(replay.san(move))
        replay.push(move)
    outcome = sp.board.outcome(claim_draw=False)
    return {
        "fen": sp.fen,
        "turn": "white" if sp.board.turn else "black",
        "legal": [m.uci() for m in sp.board.legal_moves],
        "san": san,
        "last_move": sp.history[-1] if sp.history else None,
        "in_check": sp.board.is_check(),
        "over": outcome.termination.name.lower() if outcome else None,
    }


@router.get("/v1/agents/health", summary="Which engines the agents are running on")
def agents_health():
    return service.health()


# -----------------------------------------------------------------------------
# Your agents
# -----------------------------------------------------------------------------
@router.get("/v1/agents", summary="Your agents")
def list_agents(db: UserDb):
    agents = rows(db.table("agents").select(AGENT_COLUMNS).order("created_at").execute())
    since = (date.today() - timedelta(days=6)).isoformat()
    usage = rows(db.table("agent_usage").select("agent_id,moves,sessions").gte("day", since).execute())
    week: dict[str, dict] = {}
    for u in usage:
        w = week.setdefault(u["agent_id"], {"moves": 0, "sessions": 0})
        w["moves"] += u["moves"]
        w["sessions"] += u["sessions"]
    return [{**a, "week": week.get(a["id"], {"moves": 0, "sessions": 0})} for a in agents]


@router.post("/v1/agents", status_code=201, summary="Hire from the library, or build your own")
def create_agent(body: AgentIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    p = persona_or_422(persona=body.persona, archetype=body.archetype, rating=body.rating)
    return save(db, by, {"name": body.name.strip(), "archetype": p["archetype"] if p["archetype"] != "custom" else None,
                         "persona": p, "notes": body.notes, "status": body.status})


@router.get("/v1/agents/{agent_id}", summary="One of your agents")
def get_agent(agent_id: str, db: UserDb):
    return mine(db, agent_id)


@router.patch("/v1/agents/{agent_id}", summary="Rename, tune, activate or pause")
def update_agent(agent_id: str, body: AgentPatch, db: UserDb, authorization: Auth = None):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    if "persona" in changes:
        p = persona_or_422(persona=changes.pop("persona"))
        save(db, caller_id(authorization), {"id": agent_id, "persona": p,
                                            **{k: changes.pop(k) for k in ("name", "notes") if k in changes}})
    if changes:
        found = rows(db.table("agents").update(changes).eq("id", agent_id).select("id").execute())
        if not found:
            raise HTTPException(status_code=404, detail="No such agent.")
    return mine(db, agent_id)


@router.post("/v1/agents/{agent_id}/copy", status_code=201, summary="Replicate an agent, optionally at another rating")
def copy_agent(agent_id: str, body: CopyIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    source = mine(db, agent_id)
    p = dict(source["persona"])
    if body.rating is not None:
        p["rating"] = body.rating
    p = persona_or_422(persona=p)
    name = body.name or f"{source['name'][:33]} (copy)"
    return save(db, by, {"name": name, "archetype": source["archetype"], "parent": source["id"], "persona": p,
                         "notes": source["notes"]})


@router.delete("/v1/agents/{agent_id}", status_code=204, summary="Delete an agent and its sessions")
def delete_agent(agent_id: str, db: UserDb):
    if not rows(db.table("agents").delete().eq("id", agent_id).select("id").execute()):
        raise HTTPException(status_code=404, detail="No such agent.")


@router.get("/v1/agents/{agent_id}/sessions", summary="Its recent games on platforms")
def agent_sessions(agent_id: str, db: UserDb, limit: int = 50):
    return rows(
        db.table("agent_sessions")
        .select("id,key_id,external_ref,color,cadence,opponent_rating,realtime,plies,status,result,started_at,last_move_at,finished_at")
        .eq("agent_id", agent_id)
        .order("started_at", desc=True)
        .limit(max(1, min(limit, 200)))
        .execute()
    )


@router.get("/v1/agents/{agent_id}/usage", summary="Moves and sessions per day")
def agent_usage(agent_id: str, db: UserDb, days: int = 30):
    since = (date.today() - timedelta(days=max(1, min(days, 365)) - 1)).isoformat()
    return rows(db.table("agent_usage").select("day,moves,sessions").eq("agent_id", agent_id).gte("day", since)
                .order("day").execute())


@router.post("/v1/agents/{agent_id}/try", summary="Playground: what it would play here, and how long it would take")
def try_agent(agent_id: str, body: TryIn, db: UserDb):
    a = mine(db, agent_id)
    p = persona_or_422(persona=a["persona"])
    sp = spot_or_422(body)
    engines_or_503()
    seed = service.new_seed()
    picks: dict[str, dict] = {}
    first = None
    try:
        for i in range(body.samples):
            out, _ = service.play_move(p, sp, state={"greeted": True}, seed=f"{seed}/{i}", cadence=body.cadence,
                                       clock_ms=body.clock_ms, opponent_rating=body.opponent_rating)
            first = first or out
            key = "resign" if out["resign"] else out["move"]
            pick = picks.setdefault(key, {"move": out["move"], "san": out["san"], "resign": out["resign"], "count": 0,
                                          "think_ms": []})
            pick["count"] += 1
            pick["think_ms"].append(out["think_ms"])
    except service.GameError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None
    choices = sorted(picks.values(), key=lambda c: -c["count"])
    for c in choices:
        times = sorted(c.pop("think_ms"))
        c["share"] = c["count"] / body.samples
        c["think_ms"] = {"min": times[0], "median": times[len(times) // 2], "max": times[-1]}
    return {"fen": sp.fen, "samples": body.samples, "choices": choices, "example": first}


@router.post("/v1/agents/difficulty", summary="How hard a position is for people, by rating")
def owner_difficulty(body: DifficultyIn, db: UserDb):
    sp = spot_or_422(body)
    engines_or_503()
    try:
        return service.difficulty(sp, ratings=body.ratings, cadence=body.cadence, clock_ms=body.clock_ms,
                                  samples=body.samples)
    except service.GameError as err:
        raise HTTPException(status_code=422, detail=str(err)) from None


# -----------------------------------------------------------------------------
# Keys
# -----------------------------------------------------------------------------
@router.get("/v1/agent-keys", summary="Your integration keys (never the keys themselves)")
def list_keys(db: UserDb):
    return rows(db.table("agent_keys").select(KEY_COLUMNS).order("created_at", desc=True).execute())


@router.post("/v1/agent-keys", status_code=201, summary="A new key - shown once")
def create_key(body: KeyIn, db: UserDb):
    made = one(db.rpc("create_agent_key", {"p_name": body.name.strip(), "p_agents": body.agents}).execute())
    return {"id": made["id"], "name": made["name"], "prefix": made["prefix"], "agent_ids": made["agentIds"],
            "created_at": made["createdAt"], "last_used_at": None, "revoked_at": None, "key": made["key"]}


@router.patch("/v1/agent-keys/{key_id}", summary="Rename a key")
def rename_key(key_id: str, body: KeyPatch, db: UserDb):
    found = rows(db.table("agent_keys").update({"name": body.name.strip()}).eq("id", key_id).select(KEY_COLUMNS).execute())
    if not found:
        raise HTTPException(status_code=404, detail="No such key.")
    return found[0]


@router.delete("/v1/agent-keys/{key_id}", status_code=204, summary="Revoke a key, for good")
def revoke_key(key_id: str, db: UserDb):
    db.rpc("revoke_agent_key", {"p_key": key_id}).execute()
