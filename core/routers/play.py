"""
Playing: rounds, pairings, moves, the clock, results, standings, the arena.

The API is the referee here. It reads the game as the caller, judges the move
with the rules engine (play/rules.py), and hands the database a signed ruling
(play/referee.py). The database decides whether the caller may act on it - the
right player, the right ply, time on the clock - so this module never has to
be trusted with that, and a client calling the database directly gets nothing
it could not get through here.

The judgement itself lives in play/service.py, shared with the embed
(routers/embed.py) and the autopilot (autopilot.py); this module reads as the
caller and signs as the caller.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Header, HTTPException
from postgrest import APIError
from pydantic import BaseModel, ConfigDict, Field

import autopilot
from db import CallerDb, UserDb, one, rows
from lookups import needs_platforms, optional_rpc
from play import pairing, service, standings
from play.referee import caller_id, sign
from routers.tournaments import find

router = APIRouter(tags=["Play"])

Auth = Annotated[Optional[str], Header(alias="Authorization")]

PERSON = "id,username,display_name,avatar_url,country"
GAME_FULL = (
    "*, tournament:tournaments(id,slug,title,game,variant,format,status,games_watchable),"
    f" white:profiles!games_white_id_fkey({PERSON}), black:profiles!games_black_id_fkey({PERSON})"
)


class MoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    move: str = Field(min_length=2, max_length=64)
    # The ply the player saw. If the game has moved on, refuse rather than
    # apply a move made against a position that no longer exists.
    ply: Optional[int] = Field(None, ge=0)


class NextIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Publish and start the clocks at once, or publish for players to see first.
    start: bool = False


class ResultIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result: Literal["white", "black", "draw", "none"]


class ExtendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # "+5 min break" on the autopilot card; added to any hold already set.
    minutes: int = Field(5, ge=1, le=120)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _variant(t: dict) -> str:
    return service.variant(t)


def _seeds(db, slug: str) -> list[pairing.Seed]:
    """Approved players in seeding order: seed, then rating, then who came first."""
    return service.seeds_from_roster(rows(db.rpc("get_roster", {"p_slug": slug}).execute()))


def _results(db, tournament_id: str) -> list[standings.Result]:
    return service.results_from_rows(rows(db.rpc("get_results", {"p_tournament": tournament_id}).execute()))


def _people(db, ids) -> dict[str, dict]:
    ids = sorted({i for i in ids if i})
    if not ids:
        return {}
    return {p["id"]: p for p in rows(db.table("profiles").select(PERSON).in_("id", ids).execute())}


def _game(db, game_id: str) -> dict:
    return one(db.table("games").select(GAME_FULL).eq("id", game_id).execute(), missing="No such game.")


def _history(db, game: dict) -> list[str]:
    moves = rows(db.table("moves").select("ply,move").eq("game_id", game["id"]).order("ply").execute())
    return service.history_of(game, moves)


def _publish(db, by: str, t: dict, round_no: Optional[int], pairs: list[pairing.Pairing], start: bool) -> list[dict]:
    games = service.pairing_games(t, pairs)
    payload, sig = sign("pairings", by, {"tournament": t["id"], "round": round_no, "start": start, "games": games})
    return rows(db.rpc("publish_pairings", {"p_payload": payload, "p_sig": sig}).execute())


# -----------------------------------------------------------------------------
# Rounds and standings
# -----------------------------------------------------------------------------
@router.get("/v1/tournaments/{slug}/rounds", summary="Pairings and results, round by round")
def list_rounds(slug: str, db: CallerDb):
    t = find(db, slug)
    results = rows(db.rpc("get_results", {"p_tournament": t["id"]}).execute())
    # Round ids come from the table, which only staff and entrants of an
    # unlisted event can read; everyone else gets the status from the results.
    round_rows = rows(db.table("rounds").select("*").eq("tournament_id", t["id"]).execute())
    names = _people(db, [g["white_id"] for g in results] + [g["black_id"] for g in results])
    return service.rounds_out(results, round_rows, names)


@router.get("/v1/tournaments/{slug}/standings", summary="The table")
def get_standings(slug: str, db: CallerDb):
    t = find(db, slug)
    seeds = _seeds(db, slug)
    results = _results(db, t["id"])
    players, lines = service.standings_table(t, seeds, results)
    names = _people(db, players)
    return service.standings_out(t, results, lines, names)


@router.post("/v1/tournaments/{slug}/rounds/next", summary="Pair the next round (or a knockout's tie-breaks)")
def next_round(slug: str, body: NextIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    t = find(db, slug)
    if t["status"] != "live":
        raise HTTPException(status_code=409, detail="Start the tournament before pairing.")
    if t["format"] == "arena":
        raise HTTPException(status_code=409, detail="An arena pairs players as they become free.")
    plan = service.plan_round(t, _seeds(db, slug), _results(db, t["id"]))
    if not isinstance(plan, service.Pair):
        # Wait, Done and CannotPair all say why in the console's own words.
        raise HTTPException(status_code=409, detail=plan.reason.capitalize() + ".")
    games = _publish(db, by, t, plan.round, plan.pairs, body.start)
    return {"round": plan.round, "games": len(games), "started": body.start}


def _rr_order(history: list[standings.Result], seeds: list[pairing.Seed]) -> list[pairing.Seed]:
    return service.rr_order(history, seeds)


@router.post("/v1/rounds/{round_id}/start", summary="Start the clocks on a published round")
def start_round(round_id: str, db: UserDb):
    return one(db.rpc("start_round", {"p_round": round_id}).execute())


# -----------------------------------------------------------------------------
# Games
# -----------------------------------------------------------------------------
@router.get("/v1/games/{game_id}", summary="A game: position, clocks, moves, players")
def get_game(game_id: str, db: CallerDb):
    g = _game(db, game_id)
    moves = rows(db.table("moves").select("ply,move,san,clock_ms,created_at").eq("game_id", game_id).order("ply").execute())
    now = db.rpc("server_now", {}).execute().data
    return {"game": g, "moves": moves, "server_now": now}


@router.get("/v1/me/games", summary="Your games in progress")
def my_games(db: UserDb, authorization: Auth = None):
    me = caller_id(authorization)
    found = rows(
        db.table("games")
        .select(GAME_FULL)
        .in_("status", ["scheduled", "live"])
        .or_(f"white_id.eq.{me},black_id.eq.{me}")
        .order("created_at", desc=True)
        .limit(20)
        .execute()
    )
    return found


@router.post("/v1/games/{game_id}/move", summary="Make a move")
def make_move(game_id: str, body: MoveIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    g = _game(db, game_id)
    service.check_mover(g, by, body.ply)
    payload, sig = sign("move", by, service.move_ruling(g, _history(db, g), body.move))
    return one(db.rpc("play_move", {"p_payload": payload, "p_sig": sig}).execute())


@router.post("/v1/games/{game_id}/flag", summary="Claim that the player to move is out of time")
def claim_flag(game_id: str, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    g = _game(db, game_id)
    service.check_live(g)
    payload, sig = sign("flag", by, service.flag_ruling(g, _history(db, g)))
    return one(db.rpc("claim_flag", {"p_payload": payload, "p_sig": sig}).execute())


@router.post("/v1/games/{game_id}/resign", summary="Resign")
def resign(game_id: str, db: UserDb):
    return one(db.rpc("resign", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/draw", summary="Offer a draw, or accept the one offered")
def offer_draw(game_id: str, db: UserDb):
    return one(db.rpc("offer_draw", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/draw/decline", summary="Decline a draw offer")
def decline_draw(game_id: str, db: UserDb):
    return one(db.rpc("decline_draw", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/result", summary="Set or correct a result (organisers)")
def set_result(game_id: str, body: ResultIn, db: UserDb):
    return one(db.rpc("set_result", {"p_game": game_id, "p_result": body.result}).execute())


# -----------------------------------------------------------------------------
# Arena
# -----------------------------------------------------------------------------
@router.post("/v1/tournaments/{slug}/arena/join", summary="Ask for your next arena game")
def arena_join(slug: str, db: UserDb, authorization: Auth = None):
    """Queue, then try to pair at once with whoever suits best. If nobody is
    waiting, you stay queued and the next player to arrive is paired with you."""
    me = caller_id(authorization)
    t = find(db, slug)
    # Already paired - by whoever arrived after you - is the answer to "give
    # me a game", not an error. Without this the player who waited was told to
    # finish a game nobody had shown them.
    current = rows(
        db.table("games")
        .select("*")
        .eq("tournament_id", t["id"])
        .neq("status", "finished")
        .or_(f"white_id.eq.{me},black_id.eq.{me}")
        .limit(1)
        .execute()
    )
    if current:
        return {"status": "paired", "game": current[0]}
    db.rpc("arena_join", {"p_tournament": t["id"]}).execute()
    waiting_ids = [q["user_id"] for q in rows(
        db.table("arena_queue").select("user_id,since").eq("tournament_id", t["id"]).order("since").execute()
    )]
    seeds = {s.id: s for s in _seeds(db, slug)}
    waiting = [seeds.get(i, pairing.Seed(i)) for i in waiting_ids]
    history = _results(db, t["id"])
    pick = pairing.arena_pick(me, waiting, service.arena_scores(waiting, history), history)
    if pick is None:
        return {"status": "waiting"}
    try:
        [game] = _publish(db, me, t, None, [pick], True)
    except Exception:
        # Someone else paired the opponent first. Still queued; the client asks again.
        return {"status": "waiting"}
    return {"status": "paired", "game": game}


@router.post("/v1/tournaments/{slug}/arena/leave", summary="Stop being paired")
def arena_leave(slug: str, db: UserDb):
    t = find(db, slug)
    db.rpc("arena_leave", {"p_tournament": t["id"]}).execute()
    return {"status": "left"}


# -----------------------------------------------------------------------------
# Autopilot, from the organiser's side (docs/OCHESO_PLATFORMS.md D1, F3). The
# tick itself is routers/internal.py; these are the buttons on the autopilot
# card. Each acts as the organiser - their token, their rights - so pressing
# "Pair now" while the tick pairs the same round is the database's to settle:
# one of the two gets a 409, and nothing is paired twice.
# -----------------------------------------------------------------------------
@router.get("/v1/tournaments/{slug}/autopilot", summary="What autopilot will do next, and what it did")
def autopilot_status(slug: str, db: UserDb):
    t = find(db, slug)
    round_rows = rows(db.table("rounds").select("*").eq("tournament_id", t["id"]).execute())
    results = rows(db.rpc("get_results", {"p_tournament": t["id"]}).execute())
    entrants = len(rows(db.rpc("get_roster", {"p_slug": slug}).execute()))
    # Organisers only (null for anyone else), and only with db/platforms.sql.
    info = optional_rpc(db, "get_autopilot", {"p_tournament": t["id"]}) or {}
    state = info.get("state") or {}
    now = datetime.now(timezone.utc)
    enabled = bool(t.get("autopilot"))
    hold = state.get("hold_until") or state.get("next_check_at")
    return {
        "enabled": enabled,
        "next": autopilot.next_step(t, round_rows, results, entrants, now, hold) if enabled else None,
        "timeline": autopilot.timeline(t, round_rows, results, entrants, now),
        "note": t.get("autopilot_note"),
        "last_error": state.get("last_error"),
        "last_action": state.get("last_action"),
        "last_action_at": state.get("last_action_at"),
        "hold_until": state.get("hold_until"),
        "postponed": state.get("postponed"),
        "due": info.get("due"),
        # The switch the founder flips after deploying (private.platform_settings).
        "platform_enabled": info.get("platform_enabled"),
    }


def _control(slug: str, db, action: str, minutes: Optional[int] = None) -> dict:
    t = find(db, slug)
    params = {"p_tournament": t["id"], "p_action": action}
    if minutes is not None:
        params["p_minutes"] = minutes
    try:
        return one(db.rpc("autopilot_control", params).execute())
    except APIError as e:
        needs_platforms(e)


@router.post("/v1/tournaments/{slug}/autopilot/pause", summary="Pause autopilot (clocks still run out)")
def autopilot_pause(slug: str, db: UserDb):
    return _control(slug, db, "pause")


@router.post("/v1/tournaments/{slug}/autopilot/resume", summary="Resume autopilot")
def autopilot_resume(slug: str, db: UserDb):
    return _control(slug, db, "resume")


@router.post("/v1/tournaments/{slug}/autopilot/start-now", summary="Start now, and pair round one")
def autopilot_start_now(slug: str, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    t = find(db, slug)
    if t["status"] != "registration":
        raise HTTPException(status_code=409, detail="Only a tournament taking entries can be started.")
    # Pending invites lapse and free their seats as it goes live (the database's doing).
    t = one(db.rpc("set_tournament_status", {"p_tournament": t["id"], "p_status": "live"}).execute())
    if t["format"] == "arena":
        return {"status": "live", "round": None, "games": 0}
    plan = service.plan_round(t, _seeds(db, slug), _results(db, t["id"]))
    if not isinstance(plan, service.Pair):
        # Live but unpaired: say why. Autopilot (if on) tries again by itself.
        return {"status": "live", "round": None, "games": 0, "reason": plan.reason.capitalize() + "."}
    games = _publish(db, by, t, plan.round, plan.pairs, True)
    return {"status": "live", "round": plan.round, "games": len(games)}


@router.post("/v1/tournaments/{slug}/autopilot/pair-now", summary="Pair the next round now and start it")
def autopilot_pair_now(slug: str, db: UserDb, authorization: Auth = None):
    return next_round(slug, NextIn(start=True), db, authorization)


@router.post("/v1/tournaments/{slug}/autopilot/extend-break", summary="Hold the next round a few minutes longer")
def autopilot_extend_break(slug: str, db: UserDb, body: Optional[ExtendIn] = None):
    return _control(slug, db, "extend-break", (body or ExtendIn()).minutes)
