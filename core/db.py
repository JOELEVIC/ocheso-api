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

from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from fastapi import Depends, Header, HTTPException
from postgrest import APIError, SyncPostgrestClient

from config import settings
from play.referee import sign_request
from tokens import PLATFORM_PREFIXES


class Refusal(HTTPException):
    """An HTTPException that also names a stable `code`, so a client can branch
    on {detail, code} without parsing sentences written for people. Raised
    plain, an HTTPException still gets a code from its status (web.py)."""

    def __init__(self, status_code: int, detail: Any = None, code: Optional[str] = None,
                 headers: Optional[dict[str, str]] = None) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


# The code an answer carries when nothing more specific was said.
CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "too_large",
    422: "invalid",
    429: "rate_limited",
    500: "internal",
    503: "unavailable",
}


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
    # An Ocheso key or session sent where a sign-in token belongs. Refused here,
    # before any request is built: forwarded, it would sit in the gateway's
    # logs (they record Authorization) and PostgREST would only say "bad JWT".
    # Org keys go to /v1/platform/*, player tokens to POST /v1/embed/sessions,
    # sessions in X-Ocheso-Session, agent keys to /v1/connect - each of which
    # sends the database a hash, never the token (docs/OCHESO_PLATFORMS.md B).
    if token.strip().lower().startswith(PLATFORM_PREFIXES):
        raise Refusal(
            401,
            "This route takes a sign-in token. Ocheso keys and sessions (ochs_, ochp_, oche_, och_) "
            "are never sent here.",
            code="wrong_token",
        )
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


def anon_db() -> SyncPostgrestClient:
    """As an anonymous visitor, whoever is asking. For platforms holding an agent
    key (routers/connect.py): they have no account, and their requests carry the
    API's signature instead, which the database checks."""
    return _client(settings.SUPABASE_ANON_KEY)


def jwt_db(authorization: Optional[str]) -> SyncPostgrestClient:
    """user_db outside a dependency, for routes that take a sign-in token only
    sometimes (an embed preview)."""
    return user_db(authorization)


# -----------------------------------------------------------------------------
# The three platform dispatchers (db/platforms.sql). Like the agents' calls
# (agent_routes/connect.py), a request goes in as anon, signed by this API with
# REFEREE_SECRET (play/referee.py sign_request): the signature is the gate, the
# `kind` inside it picks what the dispatcher does, and each dispatcher answers
# only its own whitelist of kinds. Keys, player tokens and sessions travel as
# SHA-256 hashes inside the signed payload - never as a bearer, never in a URL.
#
#   embed_call   emb-*   embed sessions and the frame's public reads
#   org_call     org-*   a platform's server holding an ochs_ key
#   system_call  sys-*   the autopilot tick
# -----------------------------------------------------------------------------
def _dispatch(fn: str, kind: str, body: dict, off: str) -> Any:
    payload, sig = sign_request(kind, body, off=off)
    return anon_db().rpc(fn, {"p_payload": payload, "p_sig": sig}).execute().data


def embed_call(kind: str, body: dict) -> Any:
    return _dispatch("embed_call", kind, body, "Embeds aren't switched on yet: the API has no signing key.")


def org_call(kind: str, body: dict) -> Any:
    return _dispatch("org_call", kind, body, "The platform API isn't switched on yet: the API has no signing key.")


def system_call(kind: str, body: dict) -> Any:
    return _dispatch("system_call", kind, body, "The autopilot isn't switched on yet: the API has no signing key.")


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
    "40001": 409,     # serialization_failure - e.g. a move recorded twice for one turn
    "PGRST301": 401,  # JWT expired / invalid
    "PGRST302": 401,
    # Ocheso's own SQLSTATEs (db/platforms.sql). OC429 is private.throttle: too
    # many player tokens, sessions, handoffs, pings or embed actions in its
    # window. OC401 is a player token or embed session that is unknown,
    # expired or revoked - 401, so the frame asks the page for a new identity
    # instead of showing "forbidden". OC403 is a player token presented from a
    # page that is not on the organisation's allowed origins.
    "OC429": 429,
    "OC401": 401,
    "OC403": 403,
}

_CODE = {"OC429": "rate_limited", "OC401": "session_expired", "OC403": "origin_not_allowed"}


def fail(error: APIError) -> HTTPException:
    """Turn a database refusal into the HTTP answer that describes it."""
    code = getattr(error, "code", None) or ""
    status = _STATUS.get(code, 400)
    # Our own functions raise sentences written for people; pass those through.
    # For everything else, keep Postgres internals out of the response.
    own = code in ("P0002", "23514", "28000", "40001", "22023", "OC429", "OC401", "OC403")
    message = (error.message if own and error.message else None) or {
        401: "Your session has expired. Sign in again.",
        403: "You don't have permission to do that.",
        404: "Not found.",
        409: "That conflicts with the current state.",
        429: "Too many requests. Wait a minute and try again.",
    }.get(status, "That request could not be completed.")
    # The shortest throttle window is a minute (spec C10). Longer ones say so
    # in their own sentence; this is the floor a well-behaved client waits.
    headers = {"Retry-After": "60"} if status == 429 else None
    return Refusal(status, message, code=_CODE.get(code) or CODES.get(status, "error"), headers=headers)


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


def ts(value: Any) -> Optional[datetime]:
    """A PostgREST timestamp (ISO 8601, maybe 'Z', maybe naive) as aware UTC."""
    if value is None or isinstance(value, datetime):
        return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python before 3.11 takes only 0, 3 or 6 fractional digits.
    head, dot, rest = text.partition(".")
    if dot:
        digits = "".join(ch for ch in rest if ch.isdigit())
        tail = rest[len(digits):]
        text = f"{head}.{(digits + '000000')[:6]}{tail}"
    out = datetime.fromisoformat(text)
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)
