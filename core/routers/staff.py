"""
Co-admins and moderators. Appointed and removed by the owner alone - a co-admin
who could appoint co-admins could appoint a whole second team.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from db import UserDb, one, rows
from routers.tournaments import find
from schemas.staff import StaffIn, StaffOut, StaffRoleIn

router = APIRouter(prefix="/v1/tournaments/{slug}/staff", tags=["Staff"])

WITH_PROFILE = "*, profile:profiles!tournament_admins_user_id_fkey(id,username,display_name,avatar_url,country)"


@router.get("", response_model=list[StaffOut], summary="Who helps run it")
def list_staff(slug: str, db: UserDb):
    t = find(db, slug)
    return rows(db.table("tournament_admins").select(WITH_PROFILE).eq("tournament_id", t["id"]).order("created_at").execute())


@router.post("", response_model=StaffOut, status_code=201, summary="Appoint a co-admin or moderator")
def appoint(slug: str, body: StaffIn, db: UserDb):
    t = find(db, slug)
    person = rows(db.table("profiles").select("id").eq("username", body.username).execute())
    if not person:
        raise HTTPException(status_code=404, detail=f"Nobody is called @{body.username}.")
    if person[0]["id"] == t["owner_id"]:
        raise HTTPException(status_code=409, detail="That's the owner - they already run it.")
    return one(
        db.table("tournament_admins")
        .insert({"tournament_id": t["id"], "user_id": person[0]["id"], "role": body.role})
        .select(WITH_PROFILE)
        .execute()
    )


@router.patch("/{staff_id}", response_model=StaffOut, summary="Change a role")
def change_role(slug: str, staff_id: str, body: StaffRoleIn, db: UserDb):
    find(db, slug)
    updated = rows(db.table("tournament_admins").update({"role": body.role}).eq("id", staff_id).select(WITH_PROFILE).execute())
    if not updated:
        raise HTTPException(status_code=404, detail="No such staff member, or you aren't the owner.")
    return updated[0]


@router.delete("/{staff_id}", status_code=204, summary="Remove from staff")
def remove(slug: str, staff_id: str, db: UserDb):
    find(db, slug)
    gone = rows(db.table("tournament_admins").delete().eq("id", staff_id).execute())
    if not gone:
        raise HTTPException(status_code=404, detail="No such staff member, or you aren't the owner.")
    return Response(status_code=204)
