from __future__ import annotations

from fastapi import APIRouter, HTTPException

from db import CallerDb, UserDb, one, rows
from schemas.profile import ProfileOut, ProfileUpdate

router = APIRouter(tags=["Profiles"])


@router.get("/v1/me", response_model=ProfileOut, summary="Your profile")
def me(db: UserDb):
    found = rows(db.rpc("me", {}).execute())
    if not found or not found[0].get("id"):
        raise HTTPException(status_code=404, detail="No profile for this account.")
    return found[0]


@router.patch("/v1/me", response_model=ProfileOut, summary="Change your profile")
def update_me(body: ProfileUpdate, db: UserDb):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    mine = me(db)
    # RLS limits this to your own row whatever id is named; the id only says
    # which row that is.
    return one(db.table("profiles").update(changes).eq("id", mine["id"]).execute())


@router.get("/v1/profiles/{username}", response_model=ProfileOut, summary="A player")
def profile(username: str, db: CallerDb):
    return one(db.table("profiles").select("*").eq("username", username).execute(), missing=f"Nobody is called @{username}.")
