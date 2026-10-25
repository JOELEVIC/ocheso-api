"""
Organisations: the console a company runs its tournaments from (Studio,
docs/OCHESO_PLATFORMS.md A1, C1, D1).

Every route runs as the signed-in caller, like the rest of the API: who may
change the brand, mint a key or add a teammate is decided by the database
(organizations' and org_members' policies, and the owner/admin checks inside
each RPC), so a route here can fail but cannot overreach. An organisation the
caller is not in reads as 404 - not 403 - so its existence is not confirmed to
strangers.

Reads that span tables (players, usage, activity) are assembled here from
what the caller's policies already let them read. They are summaries for
Studio, not records: the database holds the records.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Header, HTTPException, Path, Query, Response
from postgrest import APIError
from pydantic import BaseModel, ConfigDict

import autopilot
from db import UserDb, one, rows, ts
from links import embed_snippets, hosted_url
from lookups import needs_platforms, optional_rpc, org_by_slug
from play.referee import caller_id
from routers.tournaments import insert as insert_tournament
from schemas.org import (
    RESERVED_SLUGS,
    BlockIn,
    KeyCreate,
    MemberInvite,
    MemberRole,
    OrgCreate,
    OrgUpdate,
    SeriesCreate,
    SeriesStart,
    SeriesUpdate,
    Transfer,
    WebhookCreate,
    WebhookUpdate,
    slug_ok,
)
from schemas.tournament import TournamentFields

router = APIRouter(prefix="/v1/orgs", tags=["Organisations"])

Auth = Annotated[Optional[str], Header(alias="Authorization")]
UUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
Id = Annotated[str, Path(pattern=UUID)]

# private.plan_limit, mirrored for display only (GET .../usage). The database
# enforces its own copy; if the two ever differ, the database is right and
# this page is merely out of date.
PLAN_LIMITS = {
    "community": {"players_per_event": 64, "members": 3, "keys": 2, "webhooks": 0, "invites_per_day": 500,
                  "player_tokens_per_minute": 60},
    "club": {"players_per_event": 4096, "members": 20, "keys": 10, "webhooks": 5, "invites_per_day": 5000,
             "player_tokens_per_minute": 600},
    "federation": {"players_per_event": 4096, "members": 100, "keys": 50, "webhooks": 20, "invites_per_day": 50000,
                   "player_tokens_per_minute": 3000},
}

KEY_COLUMNS = "id,name,prefix,scopes,created_by,created_at,last_used_at,revoked_at"
HOOK_COLUMNS = ("id,url,events,active,description,consecutive_failures,first_failure_at,disabled_at,"
                "disabled_reason,created_at,updated_at")
PERSON = "id,username,display_name,avatar_url,country"


class BootstrapIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    org: OrgCreate
    tournament: TournamentFields
    series: Optional[SeriesStart] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def slugify(text: str) -> str:
    plain = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", plain)).strip("-")[:40].strip("-")


def slug_base(name: str, website: Optional[str]) -> str:
    """An address from the name, or from the website's host when the name
    gives too little (a name in another script, two letters)."""
    base = slugify(name)
    if len(base) < 3 and website:
        host = (urlsplit(website).hostname or "").removeprefix("www.")
        base = slugify(host.split(".")[0]) if host else base
    if len(base) < 3:
        base = (base + "-club") if base else "club"
    if base in RESERVED_SLUGS or not slug_ok(base):
        base = slugify(base + "-org")
    return base[:34].strip("-")


def candidates(base: str, n: int = 30):
    yield base
    for i in range(2, n + 2):
        yield f"{base}-{i}"


def create_org(db, body: OrgCreate) -> dict:
    """create_organization, with a derived slug made unique by a numeric
    suffix when the caller gave none. A slug the caller chose is theirs or
    nothing: taken means 409."""
    params = {
        "p_name": body.name,
        "p_website": body.website,
        "p_brand": body.brand.model_dump(exclude_none=True) if body.brand else None,
        "p_origins": body.allowed_origins,
        "p_timezone": body.timezone,
    }
    if body.slug:
        return one(db.rpc("create_organization", {"p_slug": body.slug, **params}).execute())
    for slug in candidates(slug_base(body.name, body.website)):
        try:
            return one(db.rpc("create_organization", {"p_slug": slug, **params}).execute())
        except APIError as e:
            if getattr(e, "code", None) != "23505":
                raise
    raise HTTPException(status_code=409, detail="Couldn't find a free address for this name. Choose a slug.")


def _org(db, slug: str) -> dict:
    return org_by_slug(db, slug)


def _count(db, table: str, **filters) -> int:
    q = db.table(table).select("*", count="exact", head=True)
    for k, v in filters.items():
        q = q.in_(k, v) if isinstance(v, list) else q.eq(k, v)
    return q.execute().count or 0


def _tournaments(db, org_id: str, columns: str = "*") -> list[dict]:
    return rows(db.table("tournaments").select(columns).eq("org_id", org_id).order("starts_at").execute())


def _soft(fn, default):
    """A read that may meet a table the database doesn't have yet."""
    try:
        return fn()
    except APIError:
        return default


# -----------------------------------------------------------------------------
# Organisations
# -----------------------------------------------------------------------------
@router.post("", status_code=201, summary="Create an organisation (you become its owner)")
def create(body: OrgCreate, db: UserDb):
    return create_org(db, body)


@router.post("/bootstrap", status_code=201, summary="Onboarding in one call: organisation, open tournament, series")
def bootstrap(body: BootstrapIn, db: UserDb, authorization: Auth = None):
    """/platforms/start's last step (spec F2 S4): the organisation, its first
    tournament already open for entries with autopilot on, and the weekly
    series when one was chosen.

    Not one transaction - three RPCs - so a retry after a failure part-way
    picks up the organisation it already made (same name, owned by the caller,
    no events yet) instead of making "yoursite-2"."""
    me = caller_id(authorization)
    org = _reusable(db, me, body.org) or create_org(db, body.org)
    fields = body.tournament
    series, t = None, None
    if body.series:
        # A weekly event is the series' own first instance: create_series
        # makes it at once (private.series_next) - open for entries, autopilot
        # on, at the next weekday and time - so the series never makes a
        # second one for the same evening.
        template = fields.model_dump(mode="json", exclude={"starts_at"}, exclude_none=True)
        template.setdefault("autopilot", True)
        series = one(db.rpc("create_series", {
            "p_org": org["id"],
            "p_slug": body.series.slug or series_slug(body.series.title or fields.title),
            "p_title": body.series.title or fields.title,
            "p_template": template,
            "p_weekday": body.series.weekday,
            "p_local_time": body.series.local_time.isoformat(timespec="minutes"),
            "p_timezone": body.org.timezone or org.get("timezone"),
        }).execute())
        made = rows(db.table("tournaments").select("*").eq("series_id", series["id"])
                    .in_("status", ["draft", "registration"]).order("starts_at").limit(1).execute())
        t = made[0] if made else None
        # The first event is when the organiser said ("Today 19:00"), even if
        # that is not the series' weekday: the series' own rhythm takes over
        # from the next instance on (series_next counts from the latest
        # start). Without this the date chosen in onboarding was silently
        # swapped for the template's next Friday.
        chosen = fields.starts_at
        if t is not None and chosen is not None:
            chosen = chosen if chosen.tzinfo else chosen.replace(tzinfo=timezone.utc)
            current = ts(t.get("starts_at"))
            if current is None or abs((current - chosen).total_seconds()) >= 60:
                moved = rows(db.table("tournaments").update({"starts_at": chosen.isoformat()})
                             .eq("id", t["id"]).execute())
                t = moved[0] if moved else {**t, "starts_at": chosen.isoformat()}
    if t is None:
        extra = {} if fields.autopilot is not None else {"autopilot": True}
        t = insert_tournament(db, fields, org["id"], extra)
        t = one(db.rpc("set_tournament_status", {"p_tournament": t["id"], "p_status": "registration"}).execute())
    out = {"org": org, "tournament": t, "embed": embed_snippets(org["slug"], t),
           "hosted_url": hosted_url(org["slug"], t["slug"])}
    if series:
        out["series"] = series
    return out


def series_slug(title: str) -> str:
    """tournament_series.slug: 3-60, lowercase words and hyphens."""
    base = slugify(title)[:60].strip("-")
    return base if len(base) >= 3 else (base + "-weekly").strip("-")


def _reusable(db, me: str, body: OrgCreate) -> Optional[dict]:
    mine = rows(db.table("org_members").select("role, org:organizations(*)").eq("user_id", me).eq("role", "owner")
                .execute())
    for m in mine:
        o = m.get("org") or {}
        same = (body.slug and o.get("slug") == body.slug) or (not body.slug and o.get("name") == body.name)
        if not same:
            continue
        recent = ts(o.get("created_at"))
        if recent and recent > datetime.now(timezone.utc) - timedelta(days=1) and \
                _count(db, "tournaments", org_id=o["id"]) == 0:
            return o
    return None


@router.get("", summary="Your organisations, with your role in each")
def mine(db: UserDb, authorization: Auth = None):
    me = caller_id(authorization)
    found = rows(db.table("org_members").select("role, org:organizations(*)").eq("user_id", me).execute())
    return [{**m["org"], "role": m["role"]} for m in found if m.get("org")]


@router.get("/{org}", summary="One of your organisations")
def get(org: str, db: UserDb, authorization: Auth = None):
    o = _org(db, org)
    me = caller_id(authorization)
    role = rows(db.table("org_members").select("role").eq("org_id", o["id"]).eq("user_id", me).execute())
    return {**o, "role": role[0]["role"] if role else None, "limits": PLAN_LIMITS.get(o.get("plan") or "community")}


@router.patch("/{org}", summary="Name, website, brand, allowed origins, support email, timezone")
def update(org: str, body: OrgUpdate, db: UserDb):
    changes = body.model_dump(mode="json", exclude_unset=True)
    if "brand" in changes and body.brand is not None:
        changes["brand"] = body.brand.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    o = _org(db, org)
    updated = rows(db.table("organizations").update(changes).eq("id", o["id"]).execute())
    if not updated:
        raise HTTPException(status_code=403, detail="Only the owner and admins change the organisation.")
    return updated[0]


# -----------------------------------------------------------------------------
# Team
# -----------------------------------------------------------------------------
@router.get("/{org}/members", summary="The team, and invitations not yet accepted")
def members(org: str, db: UserDb):
    o = _org(db, org)
    team = rows(db.table("org_members").select(f"user_id,role,added_by,created_at,profile:profiles!org_members_user_id_fkey({PERSON})")
                .eq("org_id", o["id"]).order("created_at").execute())
    pending = _soft(lambda: rows(db.table("org_invites").select("id,email,role,status,created_at")
                                 .eq("org_id", o["id"]).eq("status", "pending").order("created_at").execute()), [])
    return {"members": team, "invites": pending}


@router.post("/{org}/members", status_code=201, summary="Invite a teammate by email")
def invite_member(org: str, body: MemberInvite, db: UserDb):
    o = _org(db, org)
    return one(db.rpc("invite_org_member", {"p_org": o["id"], "p_email": body.email, "p_role": body.role}).execute())


@router.delete("/{org}/invites/{invite_id}", status_code=204, summary="Withdraw a team invitation not yet accepted")
def revoke_member_invite(org: str, invite_id: Id, db: UserDb):
    # Joining takes a yes (accept_invite), so an invitation can wait forever,
    # holding a team seat; withdrawing it gives the seat back.
    _org(db, org)
    db.rpc("revoke_org_invite", {"p_invite": invite_id}).execute()
    return Response(status_code=204)


@router.patch("/{org}/members/{user_id}", summary="Change a teammate's role")
def set_role(org: str, user_id: Id, body: MemberRole, db: UserDb):
    o = _org(db, org)
    return one(db.rpc("set_org_member_role", {"p_org": o["id"], "p_user": user_id, "p_role": body.role}).execute())


@router.delete("/{org}/members/{user_id}", status_code=204, summary="Remove a teammate (or leave, if it's you)")
def remove_member(org: str, user_id: Id, db: UserDb, authorization: Auth = None):
    o = _org(db, org)
    if user_id.lower() == caller_id(authorization).lower():
        db.rpc("leave_org", {"p_org": o["id"]}).execute()
    else:
        db.rpc("remove_org_member", {"p_org": o["id"], "p_user": user_id}).execute()
    return Response(status_code=204)


@router.post("/{org}/transfer", summary="Hand ownership to another member")
def transfer(org: str, body: Transfer, db: UserDb):
    o = _org(db, org)
    db.rpc("transfer_org_ownership", {"p_org": o["id"], "p_user": body.user_id}).execute()
    return members(org, db)


# -----------------------------------------------------------------------------
# Keys
# -----------------------------------------------------------------------------
@router.get("/{org}/keys", summary="Secret keys (never the key itself)")
def keys(org: str, db: UserDb):
    o = _org(db, org)
    return rows(db.table("org_keys").select(KEY_COLUMNS).eq("org_id", o["id"]).order("created_at", desc=True).execute())


@router.post("/{org}/keys", status_code=201, summary="Mint a secret key - shown once")
def create_key(org: str, body: KeyCreate, db: UserDb, response: Response):
    o = _org(db, org)
    response.headers["Cache-Control"] = "no-store"
    return one(db.rpc("create_org_key", {"p_org": o["id"], "p_name": body.name, "p_scopes": body.scopes}).execute())


@router.delete("/{org}/keys/{key_id}", status_code=204, summary="Revoke a key, at once")
def revoke_key(org: str, key_id: Id, db: UserDb):
    _org(db, org)
    db.rpc("revoke_org_key", {"p_key": key_id}).execute()
    return Response(status_code=204)


# -----------------------------------------------------------------------------
# Webhooks
# -----------------------------------------------------------------------------
@router.get("/{org}/webhooks", summary="Webhook endpoints")
def webhooks(org: str, db: UserDb):
    o = _org(db, org)
    return rows(db.table("org_webhooks").select(HOOK_COLUMNS).eq("org_id", o["id"]).order("created_at").execute())


@router.post("/{org}/webhooks", status_code=201, summary="Add an endpoint - its signing secret is shown once")
def create_webhook(org: str, body: WebhookCreate, db: UserDb, response: Response):
    o = _org(db, org)
    response.headers["Cache-Control"] = "no-store"
    return one(db.rpc("create_webhook", {"p_org": o["id"], "p_url": body.url, "p_events": body.events,
                                         "p_description": body.description}).execute())


@router.patch("/{org}/webhooks/{hook_id}", summary="Change an endpoint, or switch it on or off")
def update_webhook(org: str, hook_id: Id, body: WebhookUpdate, db: UserDb):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    o = _org(db, org)
    updated = rows(db.table("org_webhooks").update(changes).eq("id", hook_id).eq("org_id", o["id"])
                   .execute())
    if not updated:
        raise HTTPException(status_code=404, detail="No such endpoint, or you can't change it.")
    return updated[0]


@router.delete("/{org}/webhooks/{hook_id}", status_code=204, summary="Delete an endpoint")
def delete_webhook(org: str, hook_id: Id, db: UserDb):
    o = _org(db, org)
    gone = rows(db.table("org_webhooks").delete().eq("id", hook_id).eq("org_id", o["id"]).execute())
    if not gone:
        raise HTTPException(status_code=404, detail="No such endpoint, or you can't delete it.")
    return Response(status_code=204)


@router.post("/{org}/webhooks/{hook_id}/test", summary="Queue a webhook.test delivery")
def test_webhook(org: str, hook_id: Id, db: UserDb):
    _org(db, org)
    return one(db.rpc("send_test_webhook", {"p_webhook": hook_id}).execute())


@router.post("/{org}/webhooks/{hook_id}/rotate", summary="New signing secret (the old one works for 24 h)")
def rotate_webhook(org: str, hook_id: Id, db: UserDb, response: Response):
    _org(db, org)
    response.headers["Cache-Control"] = "no-store"
    return one(db.rpc("rotate_webhook_secret", {"p_webhook": hook_id}).execute())


@router.get("/{org}/webhooks/{hook_id}/deliveries", summary="Recent deliveries to an endpoint")
def deliveries(org: str, hook_id: Id, db: UserDb, limit: int = Query(20, ge=1, le=100)):
    _org(db, org)
    return rows(db.rpc("webhook_deliveries", {"p_webhook": hook_id, "p_limit": limit}).execute())


@router.post("/{org}/deliveries/{delivery_id}/retry", summary="Deliver again now")
def retry(org: str, delivery_id: Annotated[str, Path(max_length=64, pattern=r"^[0-9A-Za-z-]+$")], db: UserDb):
    _org(db, org)
    return one(db.rpc("retry_delivery", {"p_delivery": delivery_id}).execute())


# -----------------------------------------------------------------------------
# Tournaments, players, installs, usage, activity
# -----------------------------------------------------------------------------
@router.get("/{org}/tournaments", summary="Live, upcoming, drafts and finished, with series and autopilot")
def org_tournaments(org: str, db: UserDb):
    o = _org(db, org)
    found = _tournaments(db, o["id"])
    series = {s["id"]: s for s in _soft(lambda: rows(db.table("tournament_series").select("id,slug,title,active")
                                                     .eq("org_id", o["id"]).execute()), [])}
    ids = [t["id"] for t in found]
    entrants: dict[str, int] = {}
    waiting: dict[str, int] = {}
    if ids:
        for p in rows(db.table("participants").select("tournament_id").in_("tournament_id", ids)
                      .eq("status", "approved").execute()):
            entrants[p["tournament_id"]] = entrants.get(p["tournament_id"], 0) + 1
        for i in _soft(lambda: rows(db.table("tournament_invites").select("tournament_id").in_("tournament_id", ids)
                                    .eq("status", "pending").execute()), []):
            waiting[i["tournament_id"]] = waiting.get(i["tournament_id"], 0) + 1
    now = datetime.now(timezone.utc)
    groups: dict[str, list[dict]] = {"live": [], "upcoming": [], "drafts": [], "finished": []}
    for t in found:
        s = series.get(t.get("series_id"))
        item = {
            **t,
            "series": {"slug": s["slug"], "title": s["title"]} if s else None,
            "entrants": entrants.get(t["id"], 0),
            "invites_waiting": waiting.get(t["id"], 0),
            "autopilot_next": autopilot.brief_next(t, now) if t.get("autopilot") else None,
        }
        group = {"live": "live", "registration": "upcoming", "draft": "drafts"}.get(t["status"], "finished")
        groups[group].append(item)
    groups["finished"].sort(key=lambda t: t.get("starts_at") or "", reverse=True)
    return groups


@router.get("/{org}/players", summary="Everyone across the organisation's events: invited, entered, members")
def players(
    org: str,
    db: UserDb,
    q: Optional[str] = Query(None, max_length=100),
    status: Optional[Literal["active", "invited", "bounced", "blocked"]] = None,
    source: Optional[Literal["email", "platform", "code", "open", "invite", "added"]] = None,
    tournament: Optional[str] = Query(None, max_length=120),
    limit: int = Query(200, ge=1, le=1000),
):
    o = _org(db, org)
    found = _tournaments(db, o["id"], "id,slug,title,starts_at,status")
    if tournament:
        found = [t for t in found if t["slug"] == tournament]
    by_id = {t["id"]: t for t in found}
    ids = list(by_id)
    people: dict[str, dict] = {}

    def person(key: str, **seed) -> dict:
        p = people.setdefault(key, {"id": None, "name": None, "email": None, "status": "invited", "sources": set(),
                                    "tournaments": [], "external_id": None, "last_entry_at": None})
        for k, v in seed.items():
            if v is not None and p.get(k) in (None, "invited"):
                p[k] = v
        return p

    if ids:
        entries = rows(db.table("participants").select(
            f"user_id,tournament_id,status,joined_via,created_at,profile:profiles!participants_user_id_fkey({PERSON})"
        ).in_("tournament_id", ids).execute())
        for e in entries:
            prof = e.get("profile") or {}
            p = person(e["user_id"], id=e["user_id"], name=prof.get("display_name") or prof.get("username"))
            if e["status"] in ("approved", "pending"):
                p["status"] = "active"
            p["sources"].add(e["joined_via"])
            p["tournaments"].append(by_id[e["tournament_id"]]["slug"])
            p["last_entry_at"] = max(filter(None, [p["last_entry_at"], e["created_at"]]), default=None)
        invites = _soft(lambda: rows(db.table("tournament_invites").select(
            "email,name,status,send_error,claimed_by,tournament_id,created_at").in_("tournament_id", ids).execute()), [])
        for i in invites:
            key = i["claimed_by"] or f"email:{i['email']}"
            p = person(key, id=i["claimed_by"], name=i.get("name"), email=i["email"])
            p["email"] = p["email"] or i["email"]
            p["sources"].add("email")
            if i["status"] == "pending":
                if i.get("send_error"):
                    p["status"] = "bounced" if p["status"] != "active" else p["status"]
                slug = by_id[i["tournament_id"]]["slug"]
                if slug not in p["tournaments"]:
                    p["tournaments"].append(slug)
    members = _soft(lambda: rows(db.table("org_players").select("profile_id,external_id,email,blocked_at,last_seen_at")
                                 .eq("org_id", o["id"]).execute()), [])
    for m in members:
        if tournament and m["profile_id"] not in people:
            continue
        p = person(m["profile_id"], id=m["profile_id"])
        p["external_id"] = m["external_id"]
        p["email"] = p["email"] or m.get("email")
        p["sources"].add("platform")
        if m.get("blocked_at"):
            p["status"] = "blocked"
        elif p["status"] == "invited":
            p["status"] = "active"
    out = []
    needle = (q or "").strip().lower()
    for p in people.values():
        p["sources"] = sorted(p["sources"])
        p["events"] = len(p["tournaments"])
        if needle and needle not in (p["name"] or "").lower() and needle not in (p["email"] or "").lower() \
                and needle not in (p["external_id"] or "").lower():
            continue
        if status and p["status"] != status:
            continue
        if source and source not in p["sources"]:
            continue
        out.append(p)
    out.sort(key=lambda p: p["last_entry_at"] or "", reverse=True)
    return {"players": out[:limit], "total": len(out)}


@router.post("/{org}/players/{profile_id}/block", summary="Block (or unblock) one of your platform's players")
def block(org: str, profile_id: Id, body: BlockIn, db: UserDb):
    o = _org(db, org)
    try:
        return one(db.rpc("block_org_player", {"p_org": o["id"], "p_profile": profile_id,
                                               "p_blocked": body.blocked}).execute())
    except APIError as e:
        needs_platforms(e)


@router.get("/{org}/installs", summary="Where the embeds have been seen")
def installs(org: str, db: UserDb):
    o = _org(db, org)
    return rows(db.table("org_installs").select("*").eq("org_id", o["id"]).order("last_seen_at", desc=True).execute())


@router.get("/{org}/usage", summary="What the plan allows, and what is used")
def usage(org: str, db: UserDb):
    o = _org(db, org)
    plan = o.get("plan") or "community"
    # The database's own count (get_org_usage): limits straight from
    # private.plan_limit, and "invites today" from the very throttle bucket
    # the daily cap is enforced on - so the meter and the refusal agree. Its
    # names are mapped onto this route's. The reads below are the fallback
    # for a database without db/platforms.sql.
    got = optional_rpc(db, "get_org_usage", {"p_org": o["id"]})
    if isinstance(got, dict) and isinstance(got.get("limits"), dict):
        lim = got["limits"]
        return {
            "plan": got.get("plan") or plan,
            "badge": got.get("badge"),
            "limits": {"players_per_event": lim.get("players"), "members": lim.get("members"), "keys": lim.get("keys"),
                       "webhooks": lim.get("webhooks"), "invites_per_day": lim.get("invites_day"),
                       "player_tokens_per_minute": lim.get("player_tokens_min")},
            "used": got.get("used") or {},
        }
    found = _tournaments(db, o["id"], "id,status,max_participants")
    ids = [t["id"] for t in found]
    now = datetime.now(timezone.utc)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month = (now - timedelta(days=30)).isoformat()
    used: dict[str, Any] = {
        "members": _count(db, "org_members", org_id=o["id"]),
        "keys": _soft(lambda: db.table("org_keys").select("*", count="exact", head=True).eq("org_id", o["id"])
                      .is_("revoked_at", "null").execute().count or 0, 0),
        "webhooks": _soft(lambda: _count(db, "org_webhooks", org_id=o["id"]), 0),
        "live": sum(1 for t in found if t["status"] == "live"),
        "upcoming": sum(1 for t in found if t["status"] == "registration"),
        "invites_today": 0, "players_30d": 0, "games_30d": 0,
    }
    if ids:
        used["invites_today"] = _soft(lambda: db.table("tournament_invites").select("*", count="exact", head=True)
                                      .in_("tournament_id", ids).gte("created_at", day).execute().count or 0, 0)
        recent = rows(db.table("participants").select("user_id").in_("tournament_id", ids).gte("created_at", month)
                      .execute())
        used["players_30d"] = len({r["user_id"] for r in recent})
        used["games_30d"] = db.table("games").select("*", count="exact", head=True).in_("tournament_id", ids) \
            .gte("created_at", month).execute().count or 0
    return {"plan": plan, "limits": PLAN_LIMITS.get(plan, PLAN_LIMITS["community"]), "used": used}


@router.get("/{org}/activity", summary="The last 50 things that happened")
def activity(org: str, db: UserDb):
    o = _org(db, org)
    found = _tournaments(db, o["id"], "id,slug,title,autopilot_note,updated_at")
    by_id = {t["id"]: t for t in found}
    ids = list(by_id)
    items: list[dict] = []
    if ids:
        for e in rows(db.table("participants").select(
                f"tournament_id,status,joined_via,created_at,profile:profiles!participants_user_id_fkey({PERSON})")
                .in_("tournament_id", ids).order("created_at", desc=True).limit(50).execute()):
            prof = e.get("profile") or {}
            items.append({"at": e["created_at"], "kind": "entry", "tournament": by_id[e["tournament_id"]]["slug"],
                          "who": prof.get("display_name") or prof.get("username"), "via": e["joined_via"],
                          "status": e["status"]})
        for i in _soft(lambda: rows(db.table("tournament_invites").select("tournament_id,email,status,claimed_at,created_at")
                                    .in_("tournament_id", ids).order("created_at", desc=True).limit(50).execute()), []):
            items.append({"at": i.get("claimed_at") or i["created_at"],
                          "kind": "invite.claimed" if i["status"] == "claimed" else f"invite.{i['status']}",
                          "tournament": by_id[i["tournament_id"]]["slug"], "who": i["email"]})
        for t in found:
            if t.get("autopilot_note"):
                items.append({"at": t["updated_at"], "kind": "autopilot", "tournament": t["slug"],
                              "note": t["autopilot_note"]})
    for s in _soft(lambda: rows(db.table("org_installs").select("origin,view,first_seen_at").eq("org_id", o["id"])
                                .order("first_seen_at", desc=True).limit(20).execute()), []):
        items.append({"at": s["first_seen_at"], "kind": "install", "origin": s["origin"], "view": s["view"]})
    for k in _soft(lambda: rows(db.table("org_keys").select("name,prefix,last_used_at").eq("org_id", o["id"])
                                .not_.is_("last_used_at", "null").execute()), []):
        items.append({"at": k["last_used_at"], "kind": "key.used", "key": k["name"], "prefix": k["prefix"]})
    items.sort(key=lambda i: i.get("at") or "", reverse=True)
    return items[:50]


# -----------------------------------------------------------------------------
# Series
# -----------------------------------------------------------------------------
@router.get("/{org}/series", summary="Weekly series")
def list_series(org: str, db: UserDb):
    o = _org(db, org)
    return rows(db.table("tournament_series").select("*").eq("org_id", o["id"]).order("created_at").execute())


@router.post("/{org}/series", status_code=201, summary="Start a weekly series")
def create_series(org: str, body: SeriesCreate, db: UserDb):
    o = _org(db, org)
    template = TournamentFields.model_validate({**body.template, "title": body.template.get("title") or body.title,
                                                "starts_at": body.template.get("starts_at") or
                                                datetime.now(timezone.utc).isoformat()})
    return one(db.rpc("create_series", {
        "p_org": o["id"],
        "p_slug": body.slug or series_slug(body.title),
        "p_title": body.title,
        "p_template": template.model_dump(mode="json", exclude={"starts_at", "entry_code"}, exclude_none=True),
        "p_weekday": body.weekday,
        "p_local_time": body.local_time.isoformat(timespec="minutes"),
        "p_timezone": body.timezone or o.get("timezone"),
    }).execute())


@router.patch("/{org}/series/{series_id}", summary="Pause or resume, skip dates, change, or stop a series")
def update_series(org: str, series_id: Id, body: SeriesUpdate, db: UserDb):
    _org(db, org)
    out = None
    changes = body.model_dump(mode="json", exclude_unset=True, exclude={"active", "skip_dates", "unskip_dates", "stop"})
    if body.template is not None:
        TournamentFields.model_validate({**body.template, "title": body.template.get("title") or "Series instance",
                                         "starts_at": datetime.now(timezone.utc).isoformat()})
    if changes:
        out = one(db.rpc("update_series", {"p_series": series_id, "p_changes": changes}).execute())
    for day, skip in [(d, True) for d in body.skip_dates or []] + [(d, False) for d in body.unskip_dates or []]:
        out = one(db.rpc("skip_series_date", {"p_series": series_id, "p_date": day.isoformat(), "p_skip": skip})
                  .execute())
    if body.active is not None:
        out = one(db.rpc("pause_series", {"p_series": series_id, "p_paused": not body.active}).execute())
    if body.stop:
        out = one(db.rpc("stop_series", {"p_series": series_id}).execute())
    if out is None:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    return out
