"""
The tokens of Ocheso for Platforms, and the one key derived from the referee's.

    ochs_ + 48 hex   org secret key     server-to-server only (routers/platform.py)
    ochp_ + 48 hex   player token       10 minutes; the frame trades it for a session
    oche_ + 64 hex   embed session      every embed action, header X-Ocheso-Session
    32 hex           invite token       the link in an invitation email

All of them are random and stored only as their SHA-256 (docs/OCHESO_PLATFORMS.md
B). This API never keeps one: it checks the shape, hashes, and hands the hash
to the database inside a signed request, which is where a token is found to be
real, revoked or expired. The prefixes cannot overlap the agents key
(`^och_[0-9a-f]{48}$`, agent_routes/connect.py): after "och" comes "_" there
and a letter here, so no string matches two patterns, and a key pasted into the
wrong header is refused for its shape rather than tried.

One derived key per purpose, never a new secret: hmac_sha256(REFEREE_SECRET,
label) in hex. db/platforms.sql computes the same thing as
private.derived_key(label) with pgcrypto, and tests/test_tokens.py holds the
two to a fixture computed by Postgres itself. Note that the derived key is
used as its HEX TEXT, not decoded bytes, because that is what
`hmac(body, private.derived_key(...), 'sha256')` does on the database side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import date, datetime, timezone
from typing import Optional

from config import settings

AGENT_KEY = re.compile(r"^och_[0-9a-f]{48}$")
ORG_KEY = re.compile(r"^ochs_[0-9a-f]{48}$")
PLAYER_TOKEN = re.compile(r"^ochp_[0-9a-f]{48}$")
EMBED_SESSION = re.compile(r"^oche_[0-9a-f]{64}$")
INVITE_TOKEN = re.compile(r"^[0-9a-f]{32}$")
# The Google handoff (spec E4): the frame keeps S, 32 random bytes as hex, and
# sends h = hex(sha256(bytes S)). The popup binds h; only S redeems it.
HANDOFF_HASH = re.compile(r"^[0-9a-f]{64}$")
HANDOFF_SECRET = re.compile(r"^[0-9a-f]{64}$")

# Every prefix this family uses. db.py refuses all of them as JWT bearers so a
# platform's key never travels to PostgREST, where gateways log Authorization.
PLATFORM_PREFIXES = ("ochs_", "ochp_", "oche_", "och_")

TICK_LABEL = "ocheso:v1:tick"
IP_LABEL = "ocheso:v1:ip"
# How far a tick's own timestamp may be from ours. pg_cron fires every 10 s
# and pg_net posts within a second or two; 90 s allows for a slow queue
# without letting a captured tick be replayed much later.
TICK_WINDOW_S = 90


def sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def handoff_hash(secret_hex: str) -> str:
    """h from S: SHA-256 over S's bytes, as the frame computes it with
    crypto.subtle.digest."""
    return hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest()


def derived_key(label: str, secret: Optional[str] = None) -> str:
    """hmac_sha256(REFEREE_SECRET, label), hex - private.derived_key(label)."""
    key = settings.REFEREE_SECRET if secret is None else secret
    return hmac.new(key.encode(), label.encode(), hashlib.sha256).hexdigest()


def ip_hash(ip: str, day: Optional[date] = None, secret: Optional[str] = None) -> str:
    """The throttle's name for a client address (spec C10): hmac under the
    derived ip key of `first XFF hop || current_date`. A different value every
    day, so the hits table never holds a stable identifier for anyone, and the
    raw address never reaches the database at all."""
    day = day or datetime.now(timezone.utc).date()
    key = derived_key(IP_LABEL, secret)
    return hmac.new(key.encode(), f"{ip}{day.isoformat()}".encode(), hashlib.sha256).hexdigest()


def tick_signature(body: bytes, secret: Optional[str] = None) -> str:
    return hmac.new(derived_key(TICK_LABEL, secret).encode(), body, hashlib.sha256).hexdigest()


class BadTick(ValueError):
    pass


def verify_tick(body: bytes, signature: Optional[str], now: Optional[float] = None,
                secret: Optional[str] = None) -> dict:
    """The autopilot's knock (db/platforms.sql private.autopilot_kick): an HMAC
    over the RAW body bytes - never a re-serialisation, which would change the
    text being signed - compared in constant time, then kind and freshness.

    Without a referee key there is nothing to check against, and an unsigned
    tick would let anyone drive every tournament's clock: refuse."""
    if not (settings.REFEREE_SECRET if secret is None else secret):
        raise BadTick("the API has no signing key")
    if not signature or not hmac.compare_digest(tick_signature(body, secret), signature.strip().lower()):
        raise BadTick("bad signature")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise BadTick("not JSON") from None
    if not isinstance(data, dict) or data.get("kind") != "tick":
        raise BadTick("not a tick")
    ts = data.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise BadTick("no timestamp")
    if abs((time.time() if now is None else now) - ts) > TICK_WINDOW_S:
        raise BadTick("stale")
    return data


def webhook_signature(secret: str, msg_id: str, timestamp: int, body: str) -> str:
    """Standard Webhooks, as private.webhooks_pump signs (spec C9): v1, then
    base64 HMAC-SHA256 under the base64-decoded secret (whsec_ stripped) of
    `id.timestamp.body`. The API never sends webhooks; this is the reference the
    docs' verification snippets and tests/test_tokens.py are held to."""
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{msg_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def bearer(authorization: Optional[str]) -> str:
    """The token after "Bearer ", or ""."""
    if not authorization:
        return ""
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""
