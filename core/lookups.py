"""
Small reads several routers share, kept out of the routers so they can import
each other's helpers without importing each other.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException
from postgrest import APIError

from db import rows

# PostgREST's "no such function" (and Postgres's, through it). A database
# without db/platforms.sql answers this to the new RPCs.
MISSING_FUNCTION = ("PGRST202", "42883")


def org_by_slug(db, slug: str) -> dict:
    """An organisation the caller belongs to, by slug. Others read as 404:
    whether an organisation exists is not something a stranger learns here."""
    found = rows(db.table("organizations").select("*").eq("slug", slug).execute())
    if not found:
        raise HTTPException(status_code=404, detail="No such organisation, or you aren't in it.")
    return found[0]


def optional_rpc(db, fn: str, params: dict) -> Optional[Any]:
    """An RPC that may not exist yet. None when the function is missing, so a
    route that only adds to an answer (claims on /v1/me, autopilot detail)
    keeps answering on a database without the platforms update."""
    try:
        return db.rpc(fn, params).execute().data
    except APIError as e:
        if getattr(e, "code", None) in MISSING_FUNCTION:
            return None
        raise


def needs_platforms(e: APIError) -> None:
    """Re-raise a missing function as 503 with a reason, anything else as is."""
    if getattr(e, "code", None) in MISSING_FUNCTION:
        raise HTTPException(status_code=503, detail="This needs the platforms database update (db/platforms.sql).")
    raise e
