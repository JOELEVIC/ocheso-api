"""
The platform tokens and the keys derived from the referee's (core/tokens.py).

The derived key and the tick signature are computed twice in production - by
Postgres (private.derived_key, private.autopilot_kick) and by this API - so
they are held here to values Postgres itself produced: pgcrypto's
`encode(hmac(label, secret, 'sha256'), 'hex')` on a throwaway local database,
2026-10-25. If Python and SQL ever disagree, every tick is refused.
"""

import json
import re
import time

import pytest

import tokens
from tokens import (
    AGENT_KEY,
    EMBED_SESSION,
    INVITE_TOKEN,
    ORG_KEY,
    PLAYER_TOKEN,
    BadTick,
    derived_key,
    handoff_hash,
    ip_hash,
    tick_signature,
    verify_tick,
    webhook_signature,
)

SECRET = "test-referee-secret"

# select encode(hmac('ocheso:v1:tick', 'test-referee-secret', 'sha256'), 'hex')
PG_TICK_KEY = "544ab045607ce27e2a893d546f01e134cca0c3f6f53f41a6fcb4d21345ee8ba1"
# select encode(hmac('ocheso:v1:ip', 'test-referee-secret', 'sha256'), 'hex')
PG_IP_KEY = "ef6cf1571e5b1b295a9c134ea5f21a1f40de0d21678a9f38711f83da319d1658"
# select encode(hmac('{"kind":"tick","ts":1761400000,"nonce":"n1"}', <PG_TICK_KEY>, 'sha256'), 'hex')
PG_TICK_BODY = b'{"kind":"tick","ts":1761400000,"nonce":"n1"}'
PG_TICK_SIG = "577853c059499bb3557e1182e764b5788595a215789caf38ba9dd34f75358b25"
# select encode(hmac('203.0.113.7' || date '2026-10-25', <PG_IP_KEY>, 'sha256'), 'hex')
PG_IP_HASH = "fb85472f47219cf5bd7540acc2489a5a539b144dd071e92eb408787f45534f75"


# --- shapes ------------------------------------------------------------------

def _hex(n):
    return "ab" * (n // 2)


SAMPLES = {
    "agent": "och_" + _hex(48),
    "org": "ochs_" + _hex(48),
    "player": "ochp_" + _hex(48),
    "session": "oche_" + _hex(64),
}
PATTERNS = {"agent": AGENT_KEY, "org": ORG_KEY, "player": PLAYER_TOKEN, "session": EMBED_SESSION}


@pytest.mark.parametrize("kind", list(SAMPLES))
def test_each_token_matches_exactly_one_pattern(kind):
    # A key pasted into the wrong place is refused for its shape, never tried.
    matched = [k for k, rx in PATTERNS.items() if rx.fullmatch(SAMPLES[kind])]
    assert matched == [kind]


@pytest.mark.parametrize("bad", [
    "ochs_" + _hex(46), "ochs_" + _hex(50), "ochs_" + "AB" * 24, "ochs_" + "g" * 48,
    "oche_" + _hex(48), "ochp_" + _hex(64), " ochs_" + _hex(48), "ochs_" + _hex(48) + "\n",
])
def test_near_misses_match_nothing(bad):
    # fullmatch, as the API uses them: re's `$` would let a trailing newline in.
    assert not any(rx.fullmatch(bad) for rx in PATTERNS.values())


def test_the_agent_pattern_is_unchanged():
    # agent_routes/connect.py has its own copy; the two must stay one rule.
    from agent_routes.connect import KEY

    assert KEY.pattern == AGENT_KEY.pattern


def test_invite_tokens_are_32_hex():
    assert INVITE_TOKEN.fullmatch("0123456789abcdef" * 2)
    assert not INVITE_TOKEN.fullmatch("0123456789abcdef" * 2 + "0")
    assert not INVITE_TOKEN.fullmatch("0123456789ABCDEF" * 2)
    assert not INVITE_TOKEN.fullmatch("0123456789abcdef" * 2 + "\n")


def test_every_prefix_is_refused_as_a_bearer():
    assert set(tokens.PLATFORM_PREFIXES) == {"ochs_", "ochp_", "oche_", "och_"}


# --- the derived keys: parity with Postgres ----------------------------------

def test_derived_key_matches_postgres():
    assert derived_key("ocheso:v1:tick", SECRET) == PG_TICK_KEY
    assert derived_key("ocheso:v1:ip", SECRET) == PG_IP_KEY


def test_tick_signature_matches_postgres():
    # The key is the derived key's HEX TEXT, as pgcrypto's hmac() takes it.
    assert tick_signature(PG_TICK_BODY, SECRET) == PG_TICK_SIG


def test_ip_hash_matches_postgres():
    from datetime import date

    assert ip_hash("203.0.113.7", date(2026, 10, 25), SECRET) == PG_IP_HASH
    # A new day, a new name: the hits table never holds a stable identifier.
    assert ip_hash("203.0.113.7", date(2026, 10, 26), SECRET) != PG_IP_HASH


def test_derived_key_reads_the_configured_secret(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REFEREE_SECRET", SECRET)
    assert derived_key("ocheso:v1:tick") == PG_TICK_KEY


def test_handoff_hash_is_sha256_of_the_bytes():
    import hashlib

    s = "00" * 31 + "01"
    assert handoff_hash(s) == hashlib.sha256(bytes.fromhex(s)).hexdigest()
    assert handoff_hash(s) != hashlib.sha256(s.encode()).hexdigest()


# --- verifying a tick ---------------------------------------------------------

def _tick(ts=None, kind="tick", **extra) -> bytes:
    return json.dumps({"kind": kind, "ts": int(time.time()) if ts is None else ts, "nonce": "n", **extra}).encode()


def test_a_fresh_signed_tick_passes():
    body = _tick()
    assert verify_tick(body, tick_signature(body, SECRET), secret=SECRET)["kind"] == "tick"


def test_the_postgres_tick_passes_at_its_own_time():
    assert verify_tick(PG_TICK_BODY, PG_TICK_SIG, now=1761400000 + 30, secret=SECRET)["nonce"] == "n1"


@pytest.mark.parametrize("why,body,sig", [
    ("no signature", _tick(), None),
    ("wrong signature", _tick(), "0" * 64),
    ("signed with another key", _tick(), None),
    ("signature of other bytes", _tick(), None),
])
def test_bad_signatures_are_refused(why, body, sig):
    if why == "signed with another key":
        sig = tick_signature(body, "another-secret")
    if why == "signature of other bytes":
        sig = tick_signature(body + b" ", SECRET)
    with pytest.raises(BadTick):
        verify_tick(body, sig, secret=SECRET)


def test_the_raw_bytes_are_what_is_signed():
    # Same JSON, different spacing: a re-serialisation would accept it.
    body = _tick()
    spaced = json.dumps(json.loads(body), indent=1).encode()
    with pytest.raises(BadTick):
        verify_tick(spaced, tick_signature(body, SECRET), secret=SECRET)


@pytest.mark.parametrize("offset", [91, -91, 3600])
def test_stale_or_future_ticks_are_refused(offset):
    body = _tick(ts=int(time.time()) - offset)
    with pytest.raises(BadTick, match="stale"):
        verify_tick(body, tick_signature(body, SECRET), secret=SECRET)


@pytest.mark.parametrize("body", [
    _tick(kind="work"), b'{"ts": 1}', b"[1,2]", b"not json", json.dumps({"kind": "tick", "ts": "now"}).encode(),
    json.dumps({"kind": "tick", "ts": True}).encode(),
])
def test_only_ticks_are_ticks(body):
    with pytest.raises(BadTick):
        verify_tick(body, tick_signature(body, SECRET), now=time.time(), secret=SECRET)


def test_no_secret_no_ticks(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "REFEREE_SECRET", "")
    body = _tick()
    with pytest.raises(BadTick, match="no signing key"):
        verify_tick(body, tick_signature(body, ""))


# --- webhooks ---------------------------------------------------------------

def test_webhook_signature_matches_the_standard_webhooks_reference():
    # The test vector published with the Standard Webhooks spec.
    sig = webhook_signature("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330,
                            '{"test": 2432232314}')
    assert sig == "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


def test_webhook_signature_shape():
    assert re.match(r"^v1,[A-Za-z0-9+/]{43}=$", webhook_signature("whsec_" + "QUJD" * 8, "m", 1, "{}"))
