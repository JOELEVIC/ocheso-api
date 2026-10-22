"""
The agents' API surface, without a database: keys are checked before anything
reaches it, personas are refused field by field, positions are judged, and
realtime payloads are signed so a platform can verify them.

Ownership, keys and sessions as the database enforces them are proven in
db/test/test_agents.py; whole games through the API in db/test/e2e_agents.py.
"""

import base64
import hashlib
import hmac
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from agents import service
from agent_routes.connect import key_hash, signed_payload
from agents_main import app

client = TestClient(app)


def _token(sub: str = "00000000-0000-0000-0000-000000000001") -> dict:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return {"Authorization": f"Bearer {seg({'alg': 'HS256'})}.{seg({'sub': sub, 'role': 'authenticated'})}.sig"}


# --- keys -------------------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer och_short"}, {"Authorization": "Basic och_" + "0" * 48},
                                     {"Authorization": "Bearer " + "x" * 52}, {"X-Ocheso-Key": "och_" + "G" * 48}])
def test_platform_routes_need_a_well_formed_key(headers):
    assert client.get("/v1/connect/agents", headers=headers).status_code == 401
    assert client.post("/v1/connect/sessions", headers=headers, json={"agent": "x"}).status_code == 401


def test_only_the_keys_hash_travels():
    raw = "och_" + "ab" * 24
    assert key_hash(f"Bearer {raw}", None) == hashlib.sha256(raw.encode()).hexdigest()
    assert key_hash(None, raw) == key_hash(f"Bearer {raw}", None)


def test_platform_bodies_are_strict():
    r = client.post("/v1/connect/sessions", headers={"Authorization": "Bearer och_" + "0" * 48},
                    json={"agent": "x", "owner": "someone-else"})
    assert r.status_code == 422


# --- the owner's side ---------------------------------------------------------

def test_library_is_public_and_complete():
    lib = client.get("/v1/agents/library").json()
    ids = {a["id"] for a in lib["archetypes"]}
    assert {"typical", "coffeehouse", "grinder", "speed"} <= ids
    assert lib["ratingRange"] == [100, 2600] and lib["calibration"].startswith("v2")
    assert client.get("/v1/agents/library/grinder?rating=5000").status_code == 422


def test_hiring_needs_sign_in():
    assert client.post("/v1/agents", json={"name": "Ama", "archetype": "typical"}).status_code == 401
    assert client.get("/v1/agents").status_code == 401
    assert client.post("/v1/agent-keys", json={"name": "k"}).status_code == 401


@pytest.mark.parametrize("persona,field", [
    ({"rating": 50}, "rating"),
    ({"rating": 1200, "play": {"style": {"aggression": 2}}}, "play.style.aggression"),
    ({"rating": 1200, "clock": {"profile": "sometimes"}}, "clock.profile"),
    ({"rating": 1200, "shoeSize": 9}, "shoeSize"),
    ({"rating": 1200, "game": "checkers"}, "game"),
])
def test_bad_personas_are_refused_naming_the_field(persona, field):
    r = client.post("/v1/agents", headers=_token(), json={"name": "Ama", "persona": persona})
    assert r.status_code == 422 and field in r.json()["detail"]


def test_owner_bodies_are_strict():
    r = client.post("/v1/agents", headers=_token(), json={"name": "Ama", "owner_id": "someone"})
    assert r.status_code == 422
    r = client.patch("/v1/agents/x", headers=_token(), json={"rating": 2000})
    assert r.status_code == 422


# --- positions and payloads ---------------------------------------------------

def test_positions_are_judged():
    assert service.spot(["e2e4", "e7e5"]).fen.startswith("rnbqkbnr/pppp1ppp/8/4p3/4P3/8/PPPP1PPP/RNBQKBNR w")
    for moves, fen, why in [(["e2e5"], None, "not legal"), (["e2-e4"], None, "not UCI"),
                            (["e2e4"], "8/8/8/8/8/8/8/K6k w - - 0 1", "does not match"),
                            (None, "not a fen", "not a position"), (None, None, "Send the game's moves")]:
        with pytest.raises(service.GameError, match=why):
            service.spot(moves, fen)


def test_realtime_payloads_verify_with_the_session_secret():
    secret = "s" * 64
    signed = signed_payload(secret, {"move": "e2e4", "ply": 0, "session": "abc"})
    body = signed["data"]
    expected = hmac.new(secret.encode(), json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
                        hashlib.sha256).hexdigest()
    assert signed["sig"] == expected
    assert signed_payload("t" * 64, body)["sig"] != expected


# --- decisions (need Stockfish) ----------------------------------------------

needs_engines = pytest.mark.skipif(not shutil.which("stockfish"), reason="Stockfish not installed")


@needs_engines
def test_a_session_decision_is_repeatable():
    p = service.build_persona(archetype="grinder", rating=1500)
    sp = service.spot(["e2e4", "c7c5", "g1f3"])
    a, sa = service.play_move(p, sp, state={}, seed="s/3", cadence="5+3", clock_ms=290_000, opponent_rating=1500)
    b, sb = service.play_move(p, sp, state={}, seed="s/3", cadence="5+3", clock_ms=290_000, opponent_rating=1500)
    assert (a["move"], a["think_ms"], a["chat"]) == (b["move"], b["think_ms"], b["chat"]) and sa == sb
    assert sa["greeted"] and "mood" in sa and sa["lastOwn"]["expectedReply"]


@needs_engines
def test_paces():
    p = service.build_persona(archetype="typical", rating=1200)
    sp = service.spot(["d2d4", "d7d5"])
    human, _ = service.play_move(p, sp, state={"greeted": True}, seed="p", cadence="10+0", clock_ms=500_000, opponent_rating=None)
    hasty, _ = service.play_move(p, sp, state={"greeted": True}, seed="p", cadence="10+0", clock_ms=500_000, opponent_rating=None, pace="hasty")
    instant, _ = service.play_move(p, sp, state={"greeted": True}, seed="p", cadence="10+0", clock_ms=500_000, opponent_rating=None, pace="instant")
    assert human["move"] == hasty["move"] == instant["move"]
    assert instant["think_ms"] == 0 and hasty["think_ms"] <= max(250, human["think_ms"])


@needs_engines
def test_no_move_in_a_finished_game():
    p = service.build_persona(archetype="typical", rating=1200)
    mated = service.spot(["f2f3", "e7e5", "g2g4", "d8h4"])
    with pytest.raises(service.GameError, match="over"):
        service.play_move(p, mated, state={}, seed="x", cadence="5+0", clock_ms=None, opponent_rating=None)
