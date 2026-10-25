"""
Tournaments: create, find, change, and move through the lifecycle.

Nothing here decides who may do what. Each request runs as its caller (see
db.py), and row level security answers - so where an update matches no row, the
honest reply is 404 "not found or not yours": the database will not say which,
and neither should this.
"""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Response

from config import settings
from db import CallerDb, UserDb, one, rows
from lookups import org_by_slug
from schemas.tournament import (
    AccessOut,
    EntryCodeIn,
    MyTournament,
    TournamentCreate,
    TournamentFields,
    TournamentOut,
    TournamentUpdate,
)

router = APIRouter(prefix="/v1/tournaments", tags=["Tournaments"])

NOT_YOURS = "No such tournament, or it isn't yours to change."


def find(db, slug: str) -> dict:
    """By slug, through get_tournament() - the one read path that also reaches
    unlisted events, for anyone who holds the link."""
    found = rows(db.rpc("get_tournament", {"p_slug": slug}).execute())
    if not found:
        raise HTTPException(status_code=404, detail="No such tournament.")
    return found[0]


@router.get("", response_model=list[TournamentOut], summary="Browse listed tournaments")
def browse(
    db: CallerDb,
    status: Optional[Literal["registration", "live", "finished"]] = None,
    game: Optional[Literal["chess", "checkers"]] = None,
    limit: int = Query(50, ge=1, le=100),
):
    # Drafts and unlisted events never appear: the read policy leaves them out,
    # and these filters say so in the request as well as in the database.
    q = (
        db.table("tournaments")
        .select("*")
        .eq("is_listed", True)
        .in_("status", [status] if status else ["registration", "live", "finished"])
        .order("starts_at")
        .limit(limit)
    )
    if game:
        q = q.eq("game", game)
    return rows(q.execute())


@router.get("/mine", response_model=list[MyTournament], summary="Everything you run or play in")
def mine(db: UserDb):
    return rows(db.rpc("my_tournaments", {}).execute())


@router.post("", response_model=TournamentOut, status_code=201, summary="Create a tournament")
def create(body: TournamentCreate, db: UserDb):
    org_id = org_by_slug(db, body.org)["id"] if body.org else None
    return insert(db, body, org_id)


def insert(db, body: TournamentFields, org_id: Optional[str] = None, extra: Optional[dict] = None) -> dict:
    """Create a tournament as the caller - for the console, an organisation's
    Studio and the onboarding bootstrap alike."""
    data = body.model_dump(mode="json", exclude={"entry_code", "org"}, exclude_none=True)
    if org_id:
        # Insert-only by column grant: the database also checks the caller
        # may run events for this organisation.
        data["org_id"] = org_id
        # A9: an organisation's events don't move global ratings unless the
        # organiser chose that.
        data.setdefault("rated", False)
    data.update(extra or {})
    # No owner_id: the database sets it to the caller and will not take one
    # from anywhere else.
    created = one(db.table("tournaments").insert(data).execute())
    if body.entry_code:
        stored = rows(
            db.table("tournament_secrets")
            .update({"entry_code": body.entry_code.upper()})
            .eq("tournament_id", created["id"])
            .execute()
        )
        if not stored:
            # A coded event whose code never landed is one nobody can enter
            # without an invite. Say so, rather than return it as though it
            # were ready - it is still a draft, so nothing is public yet.
            raise HTTPException(
                status_code=500,
                detail=f"Created '{created['slug']}' as a draft, but the entry code was not saved. Set it from the organiser view.",
            )
    return created


@router.get("/{slug}", response_model=TournamentOut, summary="A tournament, by its link")
def get(slug: str, db: CallerDb):
    return find(db, slug)


@router.patch("/{slug}", response_model=TournamentOut, summary="Change settings")
def update(slug: str, body: TournamentUpdate, db: UserDb):
    changes = body.model_dump(mode="json", exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    updated = rows(db.table("tournaments").update(changes).eq("slug", slug).execute())
    if not updated:
        raise HTTPException(status_code=404, detail=NOT_YOURS)
    return updated[0]


@router.delete("/{slug}", status_code=204, summary="Delete a draft")
def delete(slug: str, db: UserDb):
    # Only drafts, and only by their owner - a published event keeps its
    # record. RLS enforces both; this only reports the outcome.
    gone = rows(db.table("tournaments").delete().eq("slug", slug).execute())
    if not gone:
        raise HTTPException(
            status_code=404, detail="No such draft, or it isn't yours to delete. Published events are archived, not deleted."
        )
    return Response(status_code=204)


# -----------------------------------------------------------------------------
# Lifecycle. status is not client-writable; each of these goes through
# set_tournament_status(), so the database's transition guard always runs.
# -----------------------------------------------------------------------------
def _move(slug: str, db, to: str) -> dict:
    t = find(db, slug)
    return one(db.rpc("set_tournament_status", {"p_tournament": t["id"], "p_status": to}).execute())


@router.post("/{slug}/publish", response_model=TournamentOut, summary="Open registration")
def publish(slug: str, db: UserDb):
    return _move(slug, db, "registration")


@router.post("/{slug}/unpublish", response_model=TournamentOut, summary="Back to draft, before it starts")
def unpublish(slug: str, db: UserDb):
    return _move(slug, db, "draft")


@router.post("/{slug}/start", response_model=TournamentOut, summary="Close entries and start")
def start(slug: str, db: UserDb):
    return _move(slug, db, "live")


@router.post("/{slug}/finish", response_model=TournamentOut, summary="Mark finished")
def finish(slug: str, db: UserDb):
    return _move(slug, db, "finished")


@router.post("/{slug}/archive", response_model=TournamentOut, summary="Archive")
def archive(slug: str, db: UserDb):
    return _move(slug, db, "archived")


# -----------------------------------------------------------------------------
# Access: the entry code and the invite link. Organisers only - RLS returns no
# row to anyone else, which reads here as 404.
# -----------------------------------------------------------------------------
def _access(slug: str, row: dict) -> dict:
    return {
        "entry_code": row.get("entry_code"),
        "invite_token": row["invite_token"],
        "invite_url": f"{settings.SITE_URL}/invite/{slug}?t={row['invite_token']}",
        "rotated_at": row["rotated_at"],
    }


@router.get("/{slug}/access", response_model=AccessOut, summary="Entry code and invite link")
def access(slug: str, db: UserDb):
    t = find(db, slug)
    secret = rows(db.table("tournament_secrets").select("*").eq("tournament_id", t["id"]).execute())
    if not secret:
        raise HTTPException(status_code=404, detail=NOT_YOURS)
    return _access(slug, secret[0])


@router.put("/{slug}/access/code", response_model=AccessOut, summary="Set or clear the entry code")
def set_code(slug: str, body: EntryCodeIn, db: UserDb):
    t = find(db, slug)
    code = body.entry_code.upper() if body.entry_code else None
    updated = rows(
        db.table("tournament_secrets").update({"entry_code": code}).eq("tournament_id", t["id"]).execute()
    )
    if not updated:
        raise HTTPException(status_code=404, detail=NOT_YOURS)
    return _access(slug, updated[0])


@router.post("/{slug}/access/invite/rotate", response_model=AccessOut, summary="Replace the invite link")
def rotate(slug: str, db: UserDb):
    # The remedy when a link has travelled further than intended: the old one
    # stops working the moment this returns.
    t = find(db, slug)
    db.rpc("rotate_invite", {"p_tournament": t["id"]}).execute()
    return access(slug, db)
