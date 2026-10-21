"""
The API's only door to the database.

Every request gets its own PostgREST client carrying the caller's JWT, so every
query runs as that user and row level security decides what they may see and
change (see db/schema.sql). There is no service-role client anywhere in this
API. That is the point: a bug in a router can produce a failed request, but it
cannot produce a stranger editing your tournament, because the database is the
thing saying no.

The previous version used one global client for every request. It never
forwarded the caller's token, so RLS saw every request as `anon` and could not
tell one user from another.

PostgREST verifies the JWT's signature itself, so this module never decodes or
trusts a token - it only passes it through.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import Depends, Header, HTTPException
from postgrest import APIError, SyncPostgrestClient

from config import settings


def _client(bearer: str) -> SyncPostgrestClient:
    return SyncPostgrestClient(
        f"{settings.SUPABASE_URL}/rest/v1",
        headers={
            # The gateway requires the project's public key on every request;
            # the bearer is whose request it is.
            "apikey": settings.SUPABASE_ANON_KEY,
            "Authorization": f"Bearer {bearer}",
        },
    )


def _token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Authorization must be a Bearer token.")
    return token


def caller_db(authorization: Annotated[Optional[str], Header()] = None) -> SyncPostgrestClient:
    """As the signed-in caller if there is one, otherwise as an anonymous visitor."""
    token = _token(authorization)
    return _client(token or settings.SUPABASE_ANON_KEY)


def user_db(authorization: Annotated[Optional[str], Header()] = None) -> SyncPostgrestClient:
    """As the signed-in caller. 401 without a token rather than running as anon."""
    token = _token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to do this.")
    return _client(token)


CallerDb = Annotated[SyncPostgrestClient, Depends(caller_db)]
UserDb = Annotated[SyncPostgrestClient, Depends(user_db)]


# Postgres and PostgREST error codes -> what they mean over HTTP. The old API
# answered 400 to everything, so a full tournament, an expired session and a
# typo in a slug all looked the same to the site.
_STATUS = {
    "P0002": 404,     # no_data_found - our functions use it for "no such ..."
    "PGRST116": 404,  # .single() matched no row
    "23514": 409,     # check_violation - full, not taking entries, bad transition
    "23505": 409,     # unique_violation
    "23503": 404,     # foreign_key_violation - a referenced row is missing
    "22P02": 400,     # invalid_text_representation - e.g. a malformed uuid
    "22023": 400,     # invalid_parameter_value
    "42501": 403,     # insufficient_privilege - a column this role cannot write
    "28000": 403,     # invalid_authorization - e.g. a wrong entry code
    "PGRST301": 401,  # JWT expired / invalid
    "PGRST302": 401,
}


def fail(error: APIError) -> HTTPException:
    """Turn a database refusal into the HTTP answer that describes it."""
    code = getattr(error, "code", None) or ""
    status = _STATUS.get(code, 400)
    # Our own functions raise sentences written for people; pass those through.
    # For everything else, keep Postgres internals out of the response.
    own = code in ("P0002", "23514", "28000")
    message = (error.message if own and error.message else None) or {
        401: "Your session has expired. Sign in again.",
        403: "You don't have permission to do that.",
        404: "Not found.",
        409: "That conflicts with the current state.",
    }.get(status, "That request could not be completed.")
    return HTTPException(status_code=status, detail=message)


def rows(response: Any) -> list[dict]:
    data = response.data
    # A function returning one row (me(), join_tournament()) comes back as an
    # object, not a list - and list() of a dict is its keys. That made /v1/me
    # answer 500 to every signed-in user.
    if isinstance(data, dict):
        return [data]
    return list(data or [])


def one(response: Any, missing: str = "Not found.") -> dict:
    data = response.data
    if isinstance(data, list):
        if not data:
            raise HTTPException(status_code=404, detail=missing)
        return data[0]
    if not data:
        raise HTTPException(status_code=404, detail=missing)
    return data
