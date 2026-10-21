"""
Signing rulings for the database.

A ruling is a JSON payload - what was judged, for whom, until when - and an
HMAC-SHA256 of its exact text under REFEREE_SECRET. db/play.sql verifies the
same bytes with the same key, so the payload is serialised once, here, and
passed through untouched: re-serialising on either side would change the text
and break the signature, which is the point.

`by` is the caller's id, read from their token WITHOUT verifying it. That is
safe because the database compares it with auth.uid(), which PostgREST derives
from the verified token: a forged `by` is simply refused there.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import HTTPException

from config import settings

TTL_SECONDS = 60


def caller_id(authorization: str | None) -> str:
    try:
        token = (authorization or "").split(" ", 1)[1]
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        sub = json.loads(base64.urlsafe_b64decode(part)).get("sub")
        if not sub:
            raise ValueError
        return sub
    except (IndexError, ValueError):
        raise HTTPException(status_code=401, detail="Sign in to do this.")


def sign(kind: str, by: str, body: dict[str, Any]) -> tuple[str, str]:
    if not settings.REFEREE_SECRET:
        raise HTTPException(status_code=503, detail="Play isn't switched on yet: the referee has no key.")
    payload = json.dumps(
        {**body, "kind": kind, "by": by, "exp": int(time.time()) + TTL_SECONDS},
        separators=(",", ":"),
        sort_keys=True,
    )
    sig = hmac.new(settings.REFEREE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload, sig
