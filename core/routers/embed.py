"""
The embed: what the frame at www.ocheso.com/embed/... reads and does, inside a
partner's page (docs/OCHESO_PLATFORMS.md A4, C6, D3).

Three kinds of request:

  * public reads - the bundle, an organisation's schedule, a game, the frame
    policy. Cacheable for a few seconds at the CDN and open to any origin
    (web.py PublicEmbedCors), because they carry nothing personal: the
    database's own visibility rules (get_results', games_public') decide what
    is in them, exactly as for the public site.
  * session actions - `X-Ocheso-Session: oche_...`. Whoever the player is -
    a platform's member (from a player token) or an Ocheso account (from a
    sign-in inside the frame) - they act through an embed session, and the
    frame never holds a Supabase token. The session's SHA-256 goes to the
    database inside a signed embed_call; the database finds the session,
    checks it is live and allowed to touch that tournament
    (private.session_may_touch), and acts as its player.
  * minting sessions - from a player token, from a Supabase JWT right after an
    email-code sign-in in the frame, or through the Google popup handoff.

Moves are judged here exactly as on the console (play/service.py): the
database gets a signed ruling and checks the player, the ply and the clock.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from postgrest import APIError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from config import settings
from db import Refusal, UserDb, anon_db, embed_call, jwt_db, one, rows
from links import frame_ancestors, hosted_url
from play import pairing, service
from play.standings import Result
from routers.play import MoveIn
from routers.tournaments import find
from schemas.participant import JoinIn
from tokens import EMBED_SESSION, HANDOFF_HASH, HANDOFF_SECRET, PLAYER_TOKEN, ip_hash, sha256

router = APIRouter(tags=["Embed"])
log = logging.getLogger("ocheso.embed")

UUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
GameId = Annotated[str, Path(pattern=UUID)]
Slug = Annotated[str, Path(min_length=1, max_length=120)]
TOPIC_HEX = re.compile(r"^[0-9a-f]{32}$")

PUBLIC_CACHE = "public, max-age=5, s-maxage=5, stale-while-revalidate=30"
POLICY_CACHE = "public, max-age=60, s-maxage=60, stale-while-revalidate=300"
PRIVATE = "private, no-store"

# What the bundle says about a tournament - a whitelist over
# private.tournament_public_json, so a field added there later never reaches
# partner pages without someone choosing it here too.
BUNDLE_FIELDS = ("id", "slug", "title", "description", "game", "variant", "format", "status", "starts_at",
                 "started_at", "clock", "rounds_count", "arena_minutes", "tiebreaks", "language", "identity_mode",
                 "invite_only", "requires_code", "entry", "games_watchable", "participants_visible", "series_id",
                 "autopilot")
ORG_FIELDS = ("slug", "name", "website", "brand", "badge")


# -----------------------------------------------------------------------------
# Who is asking
# -----------------------------------------------------------------------------
def session_hash(x_ocheso_session: Annotated[Optional[str], Header(alias="X-Ocheso-Session")] = None) -> str:
    if not x_ocheso_session or not EMBED_SESSION.fullmatch(x_ocheso_session.strip()):
        raise Refusal(401, "Sign in to do this: it needs an embed session (X-Ocheso-Session: oche_...).",
                      code="session_required")
    return sha256(x_ocheso_session.strip())


def optional_session(x_ocheso_session: Annotated[Optional[str], Header(alias="X-Ocheso-Session")] = None) -> Optional[str]:
    return session_hash(x_ocheso_session) if x_ocheso_session else None


Session = Annotated[str, Depends(session_hash)]
MaybeSession = Annotated[Optional[str], Depends(optional_session)]


def counted(kind: str, body: dict):
    """A brute-force-sensitive step (spec C10): the attempt is counted in a
    call of its own first, committed whatever happens next, so a run of
    failures - which roll back their own transaction - still adds up."""
    embed_call(kind, {**body, "phase": "hit"})
    return embed_call(kind, {**body, "counted": True})


def client_ip(request: Request) -> Optional[str]:
    """The throttle's key for this client (tokens.ip_hash): the first
    X-Forwarded-For hop, which Vercel sets to the address it saw."""
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() or request.headers.get("x-real-ip", "").strip() or \
        (request.client.host if request.client else "")
    if not ip or not settings.REFEREE_SECRET:
        return None
    return ip_hash(ip)


# -----------------------------------------------------------------------------
# Bodies
# -----------------------------------------------------------------------------
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MemberSessionIn(_Strict):
    player_token: str = Field(max_length=64)
    # The page the frame is in, as the browser told the frame. When the
    # organisation lists allowed origins it must be one of them.
    parent_origin: Optional[str] = Field(None, max_length=200, pattern=r"^https?://[^/\s]+$")


class AccountSessionIn(_Strict):
    slug: str = Field(min_length=1, max_length=120)


class HandoffStartIn(_Strict):
    h: str = Field(pattern=HANDOFF_HASH.pattern)
    slug: str = Field(min_length=1, max_length=120)


class HandoffBindIn(_Strict):
    h: str = Field(pattern=HANDOFF_HASH.pattern)


class HandoffRedeemIn(_Strict):
    s: str = Field(pattern=HANDOFF_SECRET.pattern)


View = Literal["tournament", "join", "standings", "pairings", "bracket", "live", "my-game", "schedule", "series", "game"]


class PingIn(_Strict):
    t: Optional[str] = Field(None, min_length=1, max_length=120)
    o: Optional[str] = Field(None, min_length=1, max_length=40)
    origin: str = Field(max_length=200, pattern=r"^https?://[^/\s]+$")
    view: View = "tournament"
    path: Optional[str] = Field(None, max_length=300, pattern=r"^/[^\s]*$")

    @model_validator(mode="after")
    def _one(self) -> "PingIn":
        if (self.t is None) == (self.o is None):
            raise ValueError("Say t (a tournament) or o (an organisation).")
        return self


# -----------------------------------------------------------------------------
# The bundle
# -----------------------------------------------------------------------------
def topic(raw: Optional[str], kind: str) -> Optional[str]:
    if not raw:
        return None
    return f"live:{kind}:{raw}" if TOPIC_HEX.fullmatch(raw) else raw


def realtime(raw_topic: Optional[str], kind: str = "t") -> Optional[dict]:
    t = topic(raw_topic, kind)
    if not t:
        return None
    return {"url": settings.SUPABASE_URL, "key": settings.SUPABASE_ANON_KEY, "topic": t}


def person(p: dict) -> dict:
    """private.person_json ({id, name, ...}) as the console's routes show a
    player ({id, display_name, ...}), so a bundle's standings read like
    /standings."""
    return {"id": p.get("id"), "display_name": p.get("display_name", p.get("name")), "username": p.get("username"),
            "avatar_url": p.get("avatar_url"), "country": p.get("country"), "kind": p.get("kind")}


def bundle_out(raw: dict) -> dict:
    """emb-bundle's read, shaped as the spec's bundle (D3): the table and the
    rounds are computed here with the same code as /standings and /rounds."""
    src = raw["tournament"]
    roster = raw.get("roster") or []
    results = raw.get("results") or []
    names = {p["id"]: person(p) for p in raw.get("people") or [] if p and p.get("id")}
    for r in roster:
        names.setdefault(r["user_id"], person({**r, "id": r["user_id"]}))
    history = service.results_from_rows(results)
    _, lines = service.standings_table(src, service.seeds_from_roster(roster), history)
    every = service.rounds_out(results, raw.get("rounds") or [], names)
    numbered = [r for r in every if r["number"] is not None]
    arena = [{**r, "games": r["games"][-100:]} for r in every if r["number"] is None]
    t = {k: src.get(k) for k in BUNDLE_FIELDS}
    if not t["clock"]:
        t["clock"] = {"base_s": src.get("clock_base_s"), "inc_s": src.get("clock_increment_s")}
    if not t["entry"]:
        cap = src.get("max_participants")
        t["entry"] = {"count": len(roster), "cap": cap, "full": bool(cap and len(roster) >= cap),
                      "open": src.get("status") == "registration"}
    t["note"] = src.get("autopilot_note")
    org = raw.get("org")
    live = [{**g, "white": names.get(g.get("white_id")), "black": names.get(g.get("black_id")),
             "topic": topic(g.get("topic"), "g")} for g in raw.get("live") or []]
    return {
        "v": 1,
        "tournament": t,
        "org": {k: org.get(k) for k in ORG_FIELDS} if org else None,
        "standings": service.standings_out(src, history, lines, names),
        "rounds": numbered[-2:] + arena,
        "live": live,
        "realtime": realtime(raw.get("topic"), "t"),
        "hosted_url": hosted_url((org or {}).get("slug"), src["slug"]),
        "rev": raw.get("rev", src.get("rev")),
        "server_now": raw.get("server_now"),
    }


# -----------------------------------------------------------------------------
# Public reads
# -----------------------------------------------------------------------------
@router.get("/v1/embed/policy", summary="Who may frame an embed: the frame-ancestors value")
def policy(response: Response, t: Optional[str] = Query(None, max_length=120), o: Optional[str] = Query(None, max_length=40),
           g: Optional[str] = Query(None, pattern=UUID)):
    if sum(x is not None for x in (t, o, g)) != 1:
        raise Refusal(400, "Ask about one thing: t, o or g.", code="bad_request")
    origins = anon_db().rpc("get_embed_policy", {"p_tournament": t, "p_org": o, "p_game": g}).execute().data
    if origins is None:
        raise HTTPException(status_code=404, detail="Nothing to embed by that name.")
    response.headers["Cache-Control"] = POLICY_CACHE
    return {"frame_ancestors": frame_ancestors(origins)}


@router.get("/v1/embed/t/{slug}", summary="Everything a tournament embed shows, in one read")
def bundle(slug: Slug, response: Response, rev: Optional[int] = Query(None, ge=0),
           preview: bool = False, authorization: Annotated[Optional[str], Header()] = None):
    if preview:
        # Studio's preview of a draft. emb-bundle shows a draft to whoever
        # the API vouches for, so the vouching is here: the caller must manage
        # the event, which reading its secrets row proves (secrets_read lets
        # managers alone see it). Never cached anywhere.
        db = jwt_db(authorization)
        t = find(db, slug)
        if not rows(db.table("tournament_secrets").select("tournament_id").eq("tournament_id", t["id"]).execute()):
            raise HTTPException(status_code=404, detail="No such tournament.")
        raw = embed_call("emb-bundle", {"slug": slug, "preview": True})
        response.headers["Cache-Control"] = PRIVATE
    else:
        raw = embed_call("emb-bundle", {"slug": slug})
        response.headers["Cache-Control"] = PUBLIC_CACHE
    if not raw or not raw.get("tournament"):
        raise HTTPException(status_code=404, detail="No such tournament.")
    return bundle_out(raw)


@router.get("/v1/embed/o/{org}", summary="An organisation's schedule: live and upcoming events, and series")
def schedule(org: Annotated[str, Path(min_length=1, max_length=40)], response: Response):
    got = one(anon_db().rpc("get_org_schedule", {"p_slug": org}).execute(), missing="No such organisation.")
    response.headers["Cache-Control"] = PUBLIC_CACHE
    o = got.get("org") or {}
    return {"org": {k: o.get(k) for k in ORG_FIELDS}, "schedule": got.get("tournaments") or [],
            "series": got.get("series") or []}


@router.get("/v1/embed/o/{org}/series/{series}", summary="A weekly series' current event (live, else next)")
def series_current(org: Annotated[str, Path(min_length=1, max_length=40)],
                   series: Annotated[str, Path(min_length=1, max_length=40)], response: Response):
    got = one(anon_db().rpc("get_series_current", {"p_org": org, "p_series_slug": series}).execute(),
              missing="No such series, or nothing scheduled.")
    response.headers["Cache-Control"] = PUBLIC_CACHE
    return got


@router.get("/v1/embed/g/{game_id}", summary="A game to watch (or yours, with a session)")
def watch(game_id: GameId, response: Response, session: MaybeSession = None):
    got = embed_call("emb-game", {"game": game_id, "session": session})
    response.headers["Cache-Control"] = PRIVATE if session else PUBLIC_CACHE
    return _game_out(got)


def _game_out(got: dict) -> dict:
    """emb-game's {game, tournament, round, white, black, moves, my_color,
    topic, server_now}, with the topic as a realtime subscription."""
    out = {k: v for k, v in got.items() if k != "topic"}
    out["realtime"] = realtime(got.get("topic"), "g")
    return out


# -----------------------------------------------------------------------------
# Sessions
# -----------------------------------------------------------------------------
@router.post("/v1/embed/sessions", status_code=201, summary="A platform's player: trade a player token for a session")
def member_session(body: MemberSessionIn, request: Request, response: Response):
    if not PLAYER_TOKEN.fullmatch(body.player_token):
        raise Refusal(401, "That isn't a player token (ochp_...). Ask the page for a new one.", code="invalid_token")
    response.headers["Cache-Control"] = "no-store"
    return counted("emb-session-member", {"token": sha256(body.player_token), "parent_origin": body.parent_origin,
                                          "ip": client_ip(request)})


@router.post("/v1/embed/sessions/account", status_code=201, summary="An Ocheso account: a session for this tournament")
def account_session(body: AccountSessionIn, response: Response, db: UserDb):
    # Right after the email-code sign-in inside the frame. The frame drops
    # the Supabase token as soon as this answers.
    response.headers["Cache-Control"] = "no-store"
    return one(db.rpc("create_account_embed_session", {"p_slug": body.slug}).execute())


@router.delete("/v1/embed/sessions/current", status_code=204, summary="Sign out of the embed")
def logout(session: Session):
    embed_call("emb-logout", {"session": session})
    return Response(status_code=204)


@router.get("/v1/me/embed-sessions", summary="Where you are signed in to embeds")
def my_sessions(db: UserDb):
    return rows(db.rpc("list_my_embed_sessions", {}).execute())


@router.delete("/v1/me/embed-sessions/{session_id}", status_code=204, summary="Sign one embed session out")
def revoke_session(session_id: Annotated[str, Path(pattern=UUID)], db: UserDb):
    db.rpc("revoke_my_embed_session", {"p_session": session_id}).execute()
    return Response(status_code=204)


# The Google handoff (spec E4). The frame keeps S and sends h = sha256(S); the
# popup, signed in first-party, binds h to its account; the frame redeems S.
# Only S redeems, and S never leaves the frame until then.
@router.post("/v1/embed/handoff/start", status_code=201, summary="Google sign-in from a frame: begin")
def handoff_start(body: HandoffStartIn, request: Request):
    return counted("emb-handoff-start", {"h": body.h, "slug": body.slug, "ip": client_ip(request)})


@router.get("/v1/embed/handoff/{h}", summary="What the popup asks you to confirm")
def handoff_peek(h: Annotated[str, Path(pattern=HANDOFF_HASH.pattern)], response: Response):
    response.headers["Cache-Control"] = "no-store"
    return embed_call("emb-handoff-peek", {"h": h})


@router.post("/v1/embed/handoff/bind", summary="The popup, signed in: this account, for that frame")
def handoff_bind(body: HandoffBindIn, db: UserDb):
    return one(db.rpc("embed_handoff_bind", {"p_hash": body.h}).execute())


@router.post("/v1/embed/handoff/redeem", summary="The frame: pending, expired, used - or the session")
def handoff_redeem(body: HandoffRedeemIn, request: Request, response: Response):
    # S itself: the database hashes it to find the handoff (only S redeems,
    # and the hash is what the popup bound). Polled every 1.5 s; each poll is
    # counted against that handoff, so S cannot be guessed at speed either.
    response.headers["Cache-Control"] = "no-store"
    return embed_call("emb-handoff-redeem", {"s": body.s, "ip": client_ip(request)})


# -----------------------------------------------------------------------------
# Acting, with a session
# -----------------------------------------------------------------------------
@router.get("/v1/embed/t/{slug}/me", summary="You in this tournament: entry, invite, current game, next round")
def me(slug: Slug, session: Session, response: Response):
    response.headers["Cache-Control"] = PRIVATE
    got = embed_call("emb-me", {"session": session, "slug": slug}) or {}
    current = got.get("current_game")
    if isinstance(current, dict) and current.get("topic"):
        current = {**current, "topic": topic(current["topic"], "g")}
        got = {**got, "current_game": current}
    return got


@router.post("/v1/embed/t/{slug}/join", summary="Enter")
def join(slug: Slug, session: Session, body: Optional[JoinIn] = None):
    # Counted first, on its own: a wrong entry code fails - and rolls back -
    # the join's transaction, so a hit counted inside it would vanish with it
    # and the code could be guessed without ever meeting a limit.
    body = body or JoinIn()
    return counted("emb-join", {"session": session, "slug": slug, "code": body.code, "invite": body.invite})


@router.post("/v1/embed/t/{slug}/withdraw", summary="Withdraw before the start")
def withdraw(slug: Slug, session: Session):
    return embed_call("emb-withdraw", {"session": session, "slug": slug})


@router.post("/v1/embed/t/{slug}/arena/join", summary="Ask for your next arena game")
def arena_join(slug: Slug, session: Session):
    """As on the console: queue, then pair at once with whoever suits best.
    The database queues and reports who is waiting; the pick is arena_pick's,
    and the pairing goes back signed for the database to check."""
    got = embed_call("emb-arena-join", {"session": session, "slug": slug}) or {}
    if got.get("status") != "queued":
        if got.get("topic"):
            got = {**got, "topic": topic(got["topic"], "g")}
        return got
    me_id = got.get("me")
    # The rules need the game and variant to set up the board; the queue
    # answer carries them ({id, slug, game, variant, format}). A bare id is an
    # older database's answer: read the event then.
    t = got["tournament"] if isinstance(got.get("tournament"), dict) else find(anon_db(), slug)
    seeds = {x["user_id"]: pairing.Seed(x["user_id"], x.get("rating") or 0) for x in got.get("seeds") or []}
    waiting = [seeds.get(q["user_id"], pairing.Seed(q["user_id"]))
               for q in sorted(got.get("queue") or [], key=lambda q: q["since"])]
    history = [Result(round=None, white=g["white_id"], black=g.get("black_id"),
                      result=g.get("result") if g.get("status") == "finished" else None,
                      game_id=g.get("game_id"), finished=g.get("status") == "finished")
               for g in got.get("results") or []]
    pick = pairing.arena_pick(me_id, waiting, service.arena_scores(waiting, history), history) if me_id else None
    if pick is None:
        return {"status": "waiting"}
    try:
        made = embed_call("emb-arena-pairings", {"session": session, "tournament": t["id"],
                                                 "games": service.pairing_games(t, [pick])})
    except APIError:
        # Someone else paired the opponent first. Still queued; ask again.
        return {"status": "waiting"}
    game = made[0] if isinstance(made, list) and made else made
    return {"status": "paired", "game": game}


@router.post("/v1/embed/t/{slug}/arena/leave", summary="Stop being paired")
def arena_leave(slug: Slug, session: Session):
    embed_call("emb-arena-leave", {"session": session, "slug": slug})
    return {"status": "left"}


@router.get("/v1/embed/games/{game_id}", summary="Your game: position, clocks, moves, players")
def game(game_id: GameId, session: Session, response: Response):
    response.headers["Cache-Control"] = PRIVATE
    return _game_out(embed_call("emb-game", {"game": game_id, "session": session}))


def _read(game_id: str, session: str) -> tuple[dict, list[str], Optional[str]]:
    got = embed_call("emb-game", {"game": game_id, "session": session}) or {}
    if not got.get("game"):
        raise HTTPException(status_code=404, detail="No such game.")
    g = {**got["game"], "tournament": got.get("tournament") or {}}
    # The session's player, by the side the database says they play.
    color = got.get("my_color")
    me_id = g.get("white_id") if color == "white" else g.get("black_id") if color == "black" else None
    return g, got.get("moves") or [], me_id


@router.post("/v1/embed/games/{game_id}/move", summary="Make a move")
def move(game_id: GameId, body: MoveIn, session: Session):
    g, moves, me_id = _read(game_id, session)
    service.check_mover(g, me_id, body.ply)
    ruling = service.move_ruling(g, service.history_of(g, moves), body.move)
    return embed_call("emb-move", {**ruling, "session": session})


@router.post("/v1/embed/games/{game_id}/flag", summary="Claim that the player to move is out of time")
def flag(game_id: GameId, session: Session):
    g, moves, _ = _read(game_id, session)
    service.check_live(g)
    return embed_call("emb-flag", {**service.flag_ruling(g, service.history_of(g, moves)), "session": session})


@router.post("/v1/embed/games/{game_id}/resign", summary="Resign")
def resign(game_id: GameId, session: Session):
    return embed_call("emb-resign", {"game": game_id, "session": session})


@router.post("/v1/embed/games/{game_id}/draw", summary="Offer a draw, or accept the one offered")
def draw(game_id: GameId, session: Session):
    return embed_call("emb-draw", {"game": game_id, "session": session})


@router.post("/v1/embed/games/{game_id}/draw/decline", summary="Decline a draw offer")
def decline(game_id: GameId, session: Session):
    return embed_call("emb-decline", {"game": game_id, "session": session})


# -----------------------------------------------------------------------------
# Installs
# -----------------------------------------------------------------------------
@router.post("/v1/embed/ping", status_code=204, summary="The frame was seen on this origin (sendBeacon, text/plain JSON)")
async def ping(request: Request):
    """Once per origin per day the frame says where it is, with the parent
    origin the browser verified - that is how Studio shows "Seen on
    yoursite.com" (spec E8). text/plain so sendBeacon needs no preflight."""
    raw = await request.body()
    if len(raw) > 2048:
        raise Refusal(413, "A ping is small.", code="too_large")
    try:
        body = PingIn.model_validate(json.loads(raw or b"{}"))
    except (ValueError, ValidationError):
        raise Refusal(400, "Send JSON: {t | o, origin, view, path}.", code="bad_request") from None
    # Only the key that applies: the database tells t from o by which is present.
    which = {"t": body.t} if body.t is not None else {"o": body.o}
    await run_in_threadpool(embed_call, "emb-ping", {
        **which, "origin": body.origin.lower(), "view": body.view, "path": body.path, "ip": client_ip(request),
    })
    return Response(status_code=204)
