"""
Entering, leaving, and the organiser deciding who is in.

There is no endpoint that writes a participant row directly, because there is
no way to in the database either: join_tournament() is the only door, and it
takes who you are from your token. The old POST /rest/v1/participants accepted
user_id and status in the body.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from db import CallerDb, UserDb, one, rows
from routers.tournaments import find
from schemas.participant import AddIn, JoinIn, ParticipantOut, RosterEntry

router = APIRouter(tags=["Participants"])

# participants has two keys into profiles (user_id, decided_by); PostgREST needs
# to be told which one carries the player's name.
WITH_PROFILE = "*, profile:profiles!participants_user_id_fkey(id,username,display_name,avatar_url,country)"


@router.get("/v1/tournaments/{slug}/roster", response_model=list[RosterEntry], summary="Who is playing")
def roster(slug: str, db: CallerDb):
    # Approved entrants with names, honouring the organiser's
    # participants_visible switch - which staff and entrants see past.
    find(db, slug)
    return rows(db.rpc("get_roster", {"p_slug": slug}).execute())


@router.get(
    "/v1/tournaments/{slug}/participants",
    response_model=list[ParticipantOut],
    summary="Every entry, including those awaiting approval",
)
def entries(slug: str, db: UserDb):
    # Staff see the whole roster; anyone else sees only their own row. That is
    # RLS's call, so a stranger gets [] here rather than a 403.
    t = find(db, slug)
    return rows(
        db.table("participants").select(WITH_PROFILE).eq("tournament_id", t["id"]).order("created_at").execute()
    )


@router.post("/v1/tournaments/{slug}/join", response_model=ParticipantOut, summary="Enter a tournament")
def join(slug: str, body: JoinIn, db: UserDb):
    # Approved straight away for an open event or an invite link; pending when
    # the organiser approves entries. Joining twice returns the existing entry.
    return one(
        db.rpc("join_tournament", {"p_slug": slug, "p_code": body.code, "p_invite": body.invite}).execute()
    )


@router.post(
    "/v1/tournaments/{slug}/participants",
    response_model=ParticipantOut,
    summary="Add a player by username (organisers)",
)
def add(slug: str, body: AddIn, db: UserDb):
    # Approved at once and recorded as 'added'; capacity and timing are the
    # database's to check (add_participant in db/schema.sql).
    t = find(db, slug)
    return one(db.rpc("add_participant", {"p_tournament": t["id"], "p_username": body.username}).execute())


@router.post("/v1/tournaments/{slug}/withdraw", response_model=ParticipantOut, summary="Withdraw before the start")
def withdraw(slug: str, db: UserDb):
    return one(db.rpc("withdraw_from_tournament", {"p_slug": slug}).execute())


@router.post("/v1/participants/{participant_id}/approve", response_model=ParticipantOut, summary="Approve an entry")
def approve(participant_id: str, db: UserDb):
    # Through decide_participant() so capacity is checked at the moment of
    # approval - the same cap joining enforces.
    return one(db.rpc("decide_participant", {"p_participant": participant_id, "p_status": "approved"}).execute())


@router.post("/v1/participants/{participant_id}/reject", response_model=ParticipantOut, summary="Reject an entry")
def reject(participant_id: str, db: UserDb):
    return one(db.rpc("decide_participant", {"p_participant": participant_id, "p_status": "rejected"}).execute())


@router.delete("/v1/participants/{participant_id}", status_code=204, summary="Remove an entrant")
def remove(participant_id: str, db: UserDb):
    gone = rows(db.table("participants").delete().eq("id", participant_id).execute())
    if not gone:
        raise HTTPException(status_code=404, detail="No such entry, or you don't run that tournament.")
    return Response(status_code=204)
