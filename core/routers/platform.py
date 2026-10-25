"""
The platform API: a partner's SERVER, holding an org secret key (`ochs_...`),
manages its tournaments and signs its own users in (docs/OCHESO_PLATFORMS.md D2).

    Authorization: Bearer ochs_...

The key never reaches the database or a log line. Its SHA-256 travels inside
a request this API signs (db.py org_call); db/platforms.sql looks the hash up,
checks the key is live, has the scope, and that its organisation is active,
and does the work as that organisation. A revoked key stops working on the
next request.

A request that carries an `Origin` header came from a browser, which means
the key is sitting in a web page for anyone to copy. It is refused before the
key is even read, so the mistake shows up the first time someone tries it
rather than after the key has leaked.

Retries: `Idempotency-Key` on a POST is hashed together with the key and
passed on; org_call keeps the first reply for 24 h (private.org_idempotency)
and answers a repeat with it instead of acting twice. Without the header the
writes are still safe to retry in effect: entering a player is an upsert,
inviting an address twice is "already".
"""

from __future__ import annotations

import re
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from db import Refusal, org_call
from links import embed_snippets, hosted_url
from play import service
from schemas.org import check_email, check_url
from schemas.tournament import TournamentFields, TournamentUpdate
from tokens import ORG_KEY, bearer, sha256

router = APIRouter(prefix="/v1/platform", tags=["Platform API (secret key)"])

IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,255}$")


def platform_key(request: Request, authorization: Annotated[Optional[str], Header()] = None) -> str:
    """The SHA-256 of a well-formed secret key, from a server."""
    if "origin" in request.headers:
        raise Refusal(400, "Secret keys are server-only. Call the platform API from your server, never from a "
                           "browser, and rotate this key if it was ever in a web page.", code="server_only")
    raw = bearer(authorization)
    if not ORG_KEY.fullmatch(raw):
        raise Refusal(401, "Send your organisation's secret key: Authorization: Bearer ochs_...", code="invalid_key")
    return sha256(raw)


Key = Annotated[str, Depends(platform_key)]
IdemHeader = Annotated[Optional[str], Header(alias="Idempotency-Key")]


def idem(key: str, header: Optional[str]) -> Optional[str]:
    """The Idempotency-Key, hashed with the key it came with (two
    organisations choosing the same string never collide), for org_call to
    store and match: kept in the database because a serverless API remembers
    nothing between two requests. org-player and org-read ignore it (a player
    token must be fresh; a read changes nothing)."""
    if header is None:
        return None
    if not IDEMPOTENCY_KEY.fullmatch(header):
        raise Refusal(400, "Idempotency-Key is 1-255 visible ASCII characters.", code="bad_idempotency_key")
    return sha256(f"{key}:{header}")


def call(kind: str, key: str, body: dict, idem_hash: Optional[str] = None):
    payload = {**body, "key": key}
    if idem_hash:
        payload["idem"] = idem_hash
    return org_call(kind, payload)


# -----------------------------------------------------------------------------
# Bodies
# -----------------------------------------------------------------------------
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _PlayerFields(_Strict):
    avatar_url: Optional[str] = Field(None, max_length=500)
    country: Optional[str] = Field(None, pattern=r"^[A-Z]{2}$")
    # Seeds the member's org-local rating the first time it is seen.
    rating: Optional[int] = Field(None, ge=100, le=3500)

    avatar_rule = field_validator("avatar_url")(check_url)


class PlayerTokenIn(_PlayerFields):
    # Your user's id on your platform. The same id is the same Ocheso player.
    external_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=60)
    # Kept as you assert it, UNVERIFIED: shown to your admins only, never used
    # to claim an invitation or to send mail.
    email: Optional[str] = Field(None, max_length=254)
    # Limit the token to one tournament, and optionally enter the player now.
    tournament: Optional[str] = Field(None, min_length=1, max_length=120)
    enter: bool = False

    email_rule = field_validator("email")(check_email)

    @model_validator(mode="after")
    def _enter_needs_tournament(self) -> "PlayerTokenIn":
        if self.enter and not self.tournament:
            raise ValueError("enter needs a tournament.")
        return self


class PlatformPlayer(_PlayerFields):
    """One of {email, name?} - invited by email - or {external_id, name,
    email?} - your own user, entered at once."""

    email: Optional[str] = Field(None, max_length=254)
    external_id: Optional[str] = Field(None, min_length=1, max_length=128)
    name: Optional[str] = Field(None, min_length=1, max_length=60)

    email_rule = field_validator("email")(check_email)

    @model_validator(mode="after")
    def _one_kind(self) -> "PlatformPlayer":
        if self.external_id is None and self.email is None:
            raise ValueError("Each player needs an email (to invite) or an external_id (your user).")
        if self.external_id is not None and not self.name:
            raise ValueError("A player with an external_id needs a name.")
        if self.external_id is None and (self.avatar_url or self.country or self.rating):
            raise ValueError("avatar_url, country and rating describe your own users: send an external_id.")
        return self


class PlayersIn(_Strict):
    players: list[PlatformPlayer] = Field(min_length=1, max_length=500)
    # For the email rows: send the invitation (in the tournament's language).
    send: bool = True
    note: Optional[str] = Field(None, max_length=500)


class PlatformTournamentIn(TournamentFields):
    pass


# -----------------------------------------------------------------------------
# Players
# -----------------------------------------------------------------------------
@router.post("/player-tokens", summary="Sign one of your users in: a 10-minute player token for the embed")
def player_token(body: PlayerTokenIn, key: Key, response: Response, idempotency_key: IdemHeader = None):
    response.headers["Cache-Control"] = "no-store"
    return call("org-player", key, body.model_dump(exclude_none=True), idem(key, idempotency_key))


@router.delete("/players/{external_id:path}", status_code=204, summary="Erase one of your users (GDPR)")
def erase(external_id: str, key: Key):
    """204 only when someone was erased. An id the organisation has no player
    for is a 404, never a quiet success: a platform that believes it erased
    someone must be right."""
    got = call("org-player-erase", key, {"external_id": _external(external_id)}) or {}
    if not got.get("erased"):
        raise Refusal(404, "No player with that external_id in your organisation (never seen, or already erased).",
                      code="not_found")
    return Response(status_code=204)


def _external(external_id: str) -> str:
    # Passed as sent: the database trims it (btrim, spaces only) exactly as it
    # did when the player was made, so normalising happens in one place.
    if not 1 <= len(external_id) <= 128:
        raise Refusal(422, "external_id is 1-128 characters.", code="invalid")
    return external_id


# -----------------------------------------------------------------------------
# Tournaments
# -----------------------------------------------------------------------------
@router.get("/tournaments", summary="Your organisation's tournaments")
def list_tournaments(key: Key):
    got = call("org-read", key, {"what": "tournaments"})
    return got.get("tournaments", []) if isinstance(got, dict) else got


@router.post("/tournaments", status_code=201, summary="Create a tournament (with embed snippets)")
def create_tournament(body: PlatformTournamentIn, key: Key, idempotency_key: IdemHeader = None):
    data = body.model_dump(mode="json", exclude_none=True)
    # A9, as in the console: an organisation's event is unrated unless asked.
    data.setdefault("rated", False)
    # ...and stays off Ocheso's public directory unless asked: a partner's
    # event is for its own page (insert_org_tournament's default). The field's
    # schema default (true, for personal events) must not decide that.
    if "is_listed" not in body.model_fields_set:
        data.pop("is_listed", None)
    got = call("org-tournament-create", key, {"tournament": data}, idem(key, idempotency_key))
    t, org = (got["tournament"], got.get("org") or {}) if "tournament" in got else (got, got.get("org") or {})
    # The branded page needs the organisation's slug, which the create reply
    # carries (private.tournament_public_json's org_slug). Without it - an
    # older database - the link is the console's page for the event.
    org_slug = org.get("slug") or t.get("org_slug")
    return {**t, "embed": embed_snippets(org_slug, t), "hosted_url": hosted_url(org_slug, t["slug"])}


@router.get("/tournaments/{slug}", summary="One tournament")
def get_tournament(slug: str, key: Key):
    got = call("org-read", key, {"what": "tournament", "slug": slug})
    return got.get("tournament", got) if isinstance(got, dict) else got


@router.patch("/tournaments/{slug}", summary="Change a tournament")
def update_tournament(slug: str, body: TournamentUpdate, key: Key):
    changes = body.model_dump(mode="json", exclude_unset=True)
    if not changes:
        raise Refusal(400, "Nothing to change.", code="bad_request")
    return call("org-tournament-update", key, {"slug": slug, "changes": changes})


def _move(slug: str, status: str, key: str, idempotency_key: Optional[str]):
    return call("org-tournament-status", key, {"slug": slug, "status": status}, idem(key, idempotency_key))


@router.post("/tournaments/{slug}/publish", summary="Open entries")
def publish(slug: str, key: Key, idempotency_key: IdemHeader = None):
    return _move(slug, "registration", key, idempotency_key)


@router.post("/tournaments/{slug}/start", summary="Close entries and start")
def start(slug: str, key: Key, idempotency_key: IdemHeader = None):
    return _move(slug, "live", key, idempotency_key)


@router.post("/tournaments/{slug}/finish", summary="Mark finished")
def finish(slug: str, key: Key, idempotency_key: IdemHeader = None):
    return _move(slug, "finished", key, idempotency_key)


@router.post("/tournaments/{slug}/archive", summary="Archive (or cancel)")
def archive(slug: str, key: Key, idempotency_key: IdemHeader = None):
    return _move(slug, "archived", key, idempotency_key)


@router.post("/tournaments/{slug}/players", summary="Add players: by email (invited) or your own users (entered)")
def add_players(slug: str, body: PlayersIn, key: Key, idempotency_key: IdemHeader = None):
    h = idem(key, idempotency_key)
    members = [(n, p) for n, p in enumerate(body.players, start=1) if p.external_id is not None]
    emails = [(n, p) for n, p in enumerate(body.players, start=1) if p.external_id is None]
    out = {"added": 0, "invited": 0, "already": 0, "errors": [], "places_left": None}

    def renumber(found: list, sent: list) -> list:
        # The database numbers refusals by position in what it was sent.
        fixed = []
        for e in found or []:
            i = e.get("row") if isinstance(e, dict) else None
            fixed.append({**e, "row": sent[i - 1][0]} if isinstance(i, int) and 1 <= i <= len(sent) else e)
        return fixed

    if members:
        got = call("org-enter", key, {"slug": slug, "players": [p.model_dump(exclude_none=True) for _, p in members]}, h)
        # org-enter lists who it entered ({external_id, profile_id, status}).
        added = got.get("added") or []
        out["added"] = len(added) if isinstance(added, list) else int(added)
        out["entered"] = added if isinstance(added, list) else []
        out["errors"] += renumber(got.get("errors"), members)
    if emails:
        rows = [{"email": p.email, "name": p.name, "note": body.note} for _, p in emails]
        got = call("org-invites", key, {"slug": slug, "rows": rows, "send": body.send}, h)
        out["invited"] = got.get("added", 0)
        out["already"] += got.get("already", 0)
        out["errors"] += renumber(got.get("invalid"), emails)
        out["places_left"] = got.get("places_left", out["places_left"])
    out["errors"].sort(key=lambda e: (e.get("row") or 0) if isinstance(e, dict) else 0)
    return out


@router.delete("/tournaments/{slug}/players/{external_id:path}", status_code=204,
               summary="Withdraw one of your users from a tournament")
def remove_player(slug: str, external_id: str, key: Key):
    call("org-remove", key, {"slug": slug, "external_id": _external(external_id)})
    return Response(status_code=204)


def _play(slug: str, key: str) -> tuple[dict, list[dict], list[dict], list[dict], dict[str, dict]]:
    """org-read 'standings': {tournament, roster, results, rounds}. The roster
    carries pending entries too and names players as `name`, by profile_id."""
    got = call("org-read", key, {"what": "standings", "slug": slug})
    roster = got.get("roster") or []
    names: dict[str, dict] = {}
    for r in roster:
        names[r["profile_id"]] = {"id": r["profile_id"], "username": r.get("username"), "display_name": r.get("name"),
                                  "kind": r.get("kind"), "external_id": r.get("external_id")}
    results = got.get("results") or []
    for g in results:  # someone removed after playing keeps their platform id
        for side in ("white", "black"):
            pid = g.get(f"{side}_id")
            if pid and pid not in names:
                names[pid] = {"id": pid, "external_id": g.get(f"{side}_external_id")}
    return got["tournament"], roster, results, got.get("rounds") or [], names


def _seeds(roster: list[dict]):
    return service.seeds_from_roster(
        [{**r, "user_id": r["profile_id"]} for r in roster if r.get("status", "approved") == "approved"])


@router.get("/tournaments/{slug}/roster", summary="Who is in, or waiting (with external_id for your users)")
def roster(slug: str, key: Key):
    got = call("org-read", key, {"what": "roster", "slug": slug})
    return got.get("roster") or []


@router.get("/tournaments/{slug}/rounds", summary="Pairings and results, round by round")
def rounds(slug: str, key: Key):
    _, _, results, round_rows, names = _play(slug, key)
    return service.rounds_out(results, round_rows, names)


@router.get("/tournaments/{slug}/standings", summary="The table")
def standings(slug: str, key: Key):
    t, roster_rows, results, _, names = _play(slug, key)
    history = service.results_from_rows(results)
    _, lines = service.standings_table(t, _seeds(roster_rows), history)
    return service.standings_out(t, history, lines, names)
