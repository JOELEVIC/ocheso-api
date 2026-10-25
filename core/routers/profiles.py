from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from postgrest import APIError

from db import CallerDb, UserDb, one, rows
from lookups import optional_rpc
from schemas.profile import MeOut, ProfileOut, ProfileUpdate

router = APIRouter(tags=["Profiles"])
log = logging.getLogger("ocheso.profiles")


def _me(db) -> dict:
    found = rows(db.rpc("me", {}).execute())
    if not found or not found[0].get("id"):
        raise HTTPException(status_code=404, detail="No profile for this account.")
    return found[0]


def _claim(db) -> list[dict]:
    """Enter the caller in every tournament an organiser invited their
    confirmed address to (claim_my_invites, db/platforms.sql) - the "when they
    log in they just see it" of docs/OCHESO_PLATFORMS.md A2. The site calls
    /v1/me once per page load, so this is where it happens for anyone whose
    sign-in trigger missed it.

    It must never cost anyone their profile: a database without the function,
    or one that refuses, still answers /v1/me, with nothing claimed."""
    try:
        got = optional_rpc(db, "claim_my_invites", {})
    except APIError as e:
        log.warning("claim_my_invites refused: %s", getattr(e, "code", None))
        return []
    if isinstance(got, dict):
        got = got.get("claimed")
    if not isinstance(got, list):
        return []  # a bare count, or nothing: no names to show
    return [{"slug": c["slug"], "title": c.get("title") or c["slug"], "starts_at": c.get("starts_at"),
             "org": c.get("org")} for c in got if isinstance(c, dict) and c.get("slug")]


@router.get("/v1/me", response_model=MeOut, summary="Your profile (and any invites it just claimed)")
def me(db: UserDb):
    claimed = _claim(db)
    return {**_me(db), "claimed": claimed}


@router.patch("/v1/me", response_model=ProfileOut, summary="Change your profile")
def update_me(body: ProfileUpdate, db: UserDb):
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to change.")
    mine = _me(db)
    # RLS limits this to your own row whatever id is named; the id only says
    # which row that is.
    return one(db.table("profiles").update(changes).eq("id", mine["id"]).execute())


@router.get("/v1/profiles/{username}", response_model=ProfileOut, summary="A player")
def profile(username: str, db: CallerDb):
    return one(db.table("profiles").select("*").eq("username", username).execute(), missing=f"Nobody is called @{username}.")
