"""
Ocheso for Platforms in front of the database: who gets in, what is sent, and
how a refusal comes back - without a database (docs/OCHESO_PLATFORMS.md B, D).

The rule this file exists for: an org key (ochs_), a player token (ochp_) or an
embed session (oche_) never travels to PostgREST as a bearer and never appears
in a payload; only its SHA-256 does, inside a request this API signed. What the
database then does with the hash is proven in db/test/test_platforms.py.
"""

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient
from postgrest import APIError

from db import fail
from fakedb import install
from main import app

client = TestClient(app)

ORG_KEY = "ochs_" + "1a" * 24
PLAYER = "ochp_" + "2b" * 24
SESSION = "oche_" + "3c" * 32
AGENT = "och_" + "4d" * 24
SECRET = "test-referee-secret"


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def jwt(sub="00000000-0000-0000-0000-000000000001") -> str:
    import base64

    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'sub': sub, 'role': 'authenticated'})}.sig"


def payloads(log) -> list[dict]:
    return [json.loads(p["p_payload"]) for kind, _, fn, p in log if kind == "rpc" and p and "p_payload" in p]


def leaked(log, *raw) -> bool:
    text = json.dumps(log, default=str)
    return any(r in text for r in raw)


# --- platform tokens are never sign-in tokens --------------------------------

JWT_ROUTES = [
    ("get", "/v1/me"),
    ("post", "/v1/tournaments"),
    ("get", "/v1/tournaments/x"),          # caller_db: optional token, still refused
    ("get", "/v1/orgs"),
    ("post", "/v1/orgs"),
    ("post", "/v1/orgs/bootstrap"),
    ("get", "/v1/me/invites"),
    ("post", "/v1/embed/sessions/account"),
    ("post", "/v1/embed/handoff/bind"),
    ("get", "/v1/embed/t/x?preview=1"),
    ("get", "/v1/me/embed-sessions"),
    ("get", "/v1/tournaments/x/autopilot"),
]


@pytest.mark.parametrize("token", [ORG_KEY, PLAYER, SESSION, AGENT, "OCHS_" + "1A" * 24])
@pytest.mark.parametrize("method,path", JWT_ROUTES)
def test_platform_tokens_are_refused_where_a_sign_in_belongs(monkeypatch, token, method, path):
    log = install(monkeypatch)
    kwargs = {"json": {}} if method == "post" else {}
    r = getattr(client, method)(path, headers={"Authorization": f"Bearer {token}"}, **kwargs)
    assert r.status_code == 401, r.text
    assert r.json()["code"] == "wrong_token"
    # Not one client was made with it, and it went nowhere else either.
    assert not any(bearer == token for _, bearer, _, _ in log)
    assert not leaked(log, token)


# --- the platform API: secret keys, from servers only -------------------------

@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer ochs_short"},
    {"Authorization": f"Basic {ORG_KEY}"},
    {"Authorization": f"Bearer {AGENT}"},
    {"Authorization": f"Bearer {PLAYER}"},
    {"Authorization": f"Bearer {SESSION}"},
    {"Authorization": f"Bearer {jwt()}"},
    {"X-Ocheso-Key": ORG_KEY},
])
def test_platform_routes_need_a_secret_key(monkeypatch, headers):
    log = install(monkeypatch)
    for method, path, body in [("get", "/v1/platform/tournaments", None),
                               ("post", "/v1/platform/player-tokens", {"external_id": "u1", "name": "Ama"}),
                               ("delete", "/v1/platform/players/u1", None)]:
        r = client.request(method.upper(), path, headers=headers, json=body)
        assert r.status_code == 401 and r.json()["code"] == "invalid_key", (path, r.text)
    assert log == []


@pytest.mark.parametrize("origin", ["https://www.ocheso.com", "https://yoursite.com", "null"])
def test_a_secret_key_from_a_browser_is_refused_before_it_is_read(monkeypatch, origin):
    log = install(monkeypatch)
    r = client.get("/v1/platform/tournaments", headers={"Authorization": f"Bearer {ORG_KEY}", "Origin": origin})
    assert r.status_code == 400 and r.json()["code"] == "server_only"
    assert "server" in r.json()["detail"]
    assert log == []


def test_only_the_keys_hash_reaches_the_database(monkeypatch):
    log = install(monkeypatch, {"org_call": {"token": "ochp_" + "0" * 48, "expires_at": "x",
                                             "player": {"id": "p", "name": "Ama"}}})
    r = client.post("/v1/platform/player-tokens", headers={"Authorization": f"Bearer {ORG_KEY}"},
                    json={"external_id": "u-42", "name": "Ama", "email": "Ama@Example.com", "tournament": "weekly",
                          "enter": True})
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    [(kind, bearer, fn, params)] = log
    assert fn == "org_call" and bearer.startswith("sb_publishable")   # as anon, signed
    body = json.loads(params["p_payload"])
    assert body["kind"] == "org-player" and body["key"] == sha(ORG_KEY)
    assert body["external_id"] == "u-42" and body["email"] == "ama@example.com" and body["enter"] is True
    expected = hmac.new(SECRET.encode(), params["p_payload"].encode(), hashlib.sha256).hexdigest()
    assert params["p_sig"] == expected
    assert not leaked(log, ORG_KEY)


def test_idempotency_key_travels_hashed_with_the_key(monkeypatch):
    log = install(monkeypatch, {"org_call": {"slug": "weekly", "status": "registration"}})
    headers = {"Authorization": f"Bearer {ORG_KEY}", "Idempotency-Key": "order-7781"}
    assert client.post("/v1/platform/tournaments/weekly/publish", headers=headers).status_code == 200
    [body] = payloads(log)
    assert body["kind"] == "org-tournament-status" and body["status"] == "registration"
    assert body["idem"] == sha(f"{sha(ORG_KEY)}:order-7781")
    assert not leaked(log, "order-7781")


def test_a_malformed_idempotency_key_is_refused(monkeypatch):
    install(monkeypatch)
    r = client.post("/v1/platform/tournaments/weekly/start",
                    headers={"Authorization": f"Bearer {ORG_KEY}", "Idempotency-Key": "x" * 256})
    assert r.status_code == 400 and r.json()["code"] == "bad_idempotency_key"


@pytest.mark.parametrize("body", [
    {"external_id": "u1", "name": "Ama", "org": "someone-else"},
    {"external_id": "", "name": "Ama"},
    {"external_id": "u1", "name": "Ama", "enter": True},          # enter needs a tournament
    {"external_id": "u1", "name": "Ama", "email": "not-an-email"},
    {"external_id": "u1", "name": "Ama", "avatar_url": "javascript:alert(1)"},
    {"external_id": "u1", "name": "Ama", "rating": 5000},
])
def test_player_token_bodies_are_strict(monkeypatch, body):
    log = install(monkeypatch)
    r = client.post("/v1/platform/player-tokens", headers={"Authorization": f"Bearer {ORG_KEY}"}, json=body)
    assert r.status_code == 422 and r.json()["code"] == "invalid"
    assert log == []


def test_create_answers_with_embed_snippets(monkeypatch):
    t = {"id": "t1", "slug": "weekly-blitz", "title": 'Blitz "night" <b>', "language": "fr",
         "org": {"slug": "yoursite"}}
    log = install(monkeypatch, {"org_call": t})
    body = {"title": "Weekly Blitz", "game": "chess", "variant": "standard", "format": "arena",
            "clock_base_s": 180, "clock_increment_s": 2, "starts_at": "2026-10-30T18:00:00Z", "arena_minutes": 60,
            "identity_mode": "platform", "autopilot": True, "requires_code": True, "entry_code": "BLITZ1"}
    r = client.post("/v1/platform/tournaments", headers={"Authorization": f"Bearer {ORG_KEY}"}, json=body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["hosted_url"] == "https://www.ocheso.com/o/yoursite/weekly-blitz"
    assert 'data-ocheso-tournament="weekly-blitz"' in out["embed"]["script"]
    assert "/embed/fr/t/weekly-blitz" in out["embed"]["iframe"]
    assert "<b>" not in out["embed"]["script"] and "&lt;b&gt;" in out["embed"]["script"]
    [sent] = payloads(log)
    assert sent["kind"] == "org-tournament-create" and sent["tournament"]["rated"] is False
    assert sent["tournament"]["identity_mode"] == "platform"
    # insert_org_tournament reads the code from the tournament's own fields.
    assert sent["tournament"]["entry_code"] == "BLITZ1" and "entry_code" not in {k for k in sent if k != "tournament"}


def test_listing_is_the_databases_default_unless_asked(monkeypatch):
    # An organisation's event stays off Ocheso's public directory unless the
    # partner says otherwise: is_listed is sent only when it was set.
    body = {"title": "Weekly Blitz", "game": "chess", "variant": "standard", "format": "arena",
            "clock_base_s": 180, "starts_at": "2026-10-30T18:00:00Z", "arena_minutes": 60}
    for extra, sent_listed in (({}, None), ({"is_listed": True}, True), ({"is_listed": False}, False)):
        log = install(monkeypatch, {"org_call": {"id": "t1", "slug": "weekly-blitz", "org_slug": "yoursite"}})
        r = client.post("/v1/platform/tournaments", headers={"Authorization": f"Bearer {ORG_KEY}"}, json={**body, **extra})
        assert r.status_code == 201, r.text
        [sent] = payloads(log)
        assert sent["tournament"].get("is_listed") is sent_listed
        assert r.json()["hosted_url"] == "https://www.ocheso.com/o/yoursite/weekly-blitz"


def test_usage_reads_the_databases_count(monkeypatch):
    install(monkeypatch, {
        "organizations": [{"id": "o1", "slug": "yoursite", "plan": "club"}],
        "get_org_usage": {"plan": "club", "badge": "subtle",
                          "limits": {"players": 4096, "members": 20, "keys": 10, "webhooks": 5, "invites_day": 5000,
                                     "player_tokens_min": 600},
                          "used": {"members": 2, "keys": 1, "webhooks": 0, "invites_today": 12}},
    })
    r = client.get("/v1/orgs/yoursite/usage", headers={"Authorization": f"Bearer {jwt()}"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["limits"] == {"players_per_event": 4096, "members": 20, "keys": 10, "webhooks": 5,
                             "invites_per_day": 5000, "player_tokens_per_minute": 600}
    assert out["used"]["invites_today"] == 12 and out["badge"] == "subtle"


def test_without_the_org_slug_the_link_is_the_console_page(monkeypatch):
    install(monkeypatch, {"org_call": {"id": "t1", "slug": "weekly-blitz", "title": "Weekly"}})
    body = {"title": "Weekly Blitz", "game": "chess", "variant": "standard", "format": "arena",
            "clock_base_s": 180, "starts_at": "2026-10-30T18:00:00Z", "arena_minutes": 60}
    r = client.post("/v1/platform/tournaments", headers={"Authorization": f"Bearer {ORG_KEY}"}, json=body)
    assert r.json()["hosted_url"] == "https://www.ocheso.com/tournaments/weekly-blitz"


def test_players_split_into_entries_and_invites(monkeypatch):
    def org_call(params):
        body = json.loads(params["p_payload"])
        if body["kind"] == "org-enter":
            return {"added": [{"external_id": "u1", "profile_id": "p1", "status": "approved"}],
                    "errors": [{"row": 2, "external_id": "u2", "reason": "blocked"}]}
        return {"added": 1, "already": 1, "invalid": [{"row": 1, "reason": "bounced before"}], "places_left": 10}

    log = install(monkeypatch, {"org_call": org_call})
    players = [{"external_id": "u1", "name": "Ama"}, {"email": "kofi@example.com"},
               {"external_id": "u2", "name": "Bea"}, {"email": "Ngo@Example.com", "name": "Ngo"}]
    r = client.post("/v1/platform/tournaments/weekly/players", headers={"Authorization": f"Bearer {ORG_KEY}"},
                    json={"players": players})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["added"] == 1 and out["invited"] == 1 and out["already"] == 1 and out["places_left"] == 10
    assert out["entered"] == [{"external_id": "u1", "profile_id": "p1", "status": "approved"}]
    # Rows renumbered to the caller's own positions: u2 is 3rd, kofi is 2nd.
    assert [(e["row"], e["reason"]) for e in out["errors"]] == [(2, "bounced before"), (3, "blocked")]
    enter, invites = payloads(log)
    assert [p["external_id"] for p in enter["players"]] == ["u1", "u2"]
    assert [r["email"] for r in invites["rows"]] == ["kofi@example.com", "ngo@example.com"]


PLAY_READ = {
    "tournament": {"id": "t1", "slug": "w", "format": "swiss", "tiebreaks": ["buchholz"]},
    "roster": [
        {"participant_id": "e1", "profile_id": "a", "kind": "member", "external_id": "u1", "name": "Ama",
         "username": None, "status": "approved", "joined_via": "platform", "rating_at_entry": 1500, "seed": None,
         "joined_at": "2026-10-01T00:00:00Z"},
        {"participant_id": "e2", "profile_id": "b", "kind": "member", "external_id": "u2", "name": "Bea",
         "username": None, "status": "approved", "joined_via": "platform", "rating_at_entry": 1400, "seed": None,
         "joined_at": "2026-10-01T00:00:01Z"},
        {"participant_id": "e3", "profile_id": "c", "kind": "member", "external_id": "u3", "name": "Cid",
         "username": None, "status": "pending", "joined_via": "platform", "rating_at_entry": 1300, "seed": None,
         "joined_at": "2026-10-01T00:00:02Z"},
    ],
    "results": [{"game_id": "g", "round_number": 1, "round_status": "finished", "board": 1, "white_id": "a",
                 "black_id": "b", "white_external_id": "u1", "black_external_id": "u2", "status": "finished",
                 "result": "black", "termination": "resignation", "tiebreak_of": None,
                 "finished_at": "2026-10-01T01:00:00Z"},
                {"game_id": "h", "round_number": 1, "round_status": "finished", "board": 2, "white_id": "gone",
                 "black_id": None, "white_external_id": "u9", "black_external_id": None, "status": "finished",
                 "result": "white", "termination": "bye", "tiebreak_of": None, "finished_at": None}],
    "rounds": [{"number": 1, "status": "finished", "started_at": None, "finished_at": None}],
}


def test_standings_from_the_platform_read(monkeypatch):
    log = install(monkeypatch, {"org_call": PLAY_READ})
    r = client.get("/v1/platform/tournaments/w/standings", headers={"Authorization": f"Bearer {ORG_KEY}"})
    lines = r.json()["lines"]
    # Pending entries are not on the table; a player who left keeps their platform id.
    assert [(l["player"]["external_id"], l["points"]) for l in lines] == [("u2", 1.0), ("u9", 1.0), ("u1", 0.0)]
    assert lines[0]["player"]["display_name"] == "Bea"
    assert payloads(log)[0]["what"] == "standings"


def test_rounds_from_the_platform_read(monkeypatch):
    install(monkeypatch, {"org_call": PLAY_READ})
    [rnd] = client.get("/v1/platform/tournaments/w/rounds", headers={"Authorization": f"Bearer {ORG_KEY}"}).json()
    assert rnd["number"] == 1 and rnd["games"][0]["white"]["external_id"] == "u1"


# --- embed sessions --------------------------------------------------------------

SESSION_ROUTES = [
    ("get", "/v1/embed/t/weekly/me"),
    ("post", "/v1/embed/t/weekly/join"),
    ("post", "/v1/embed/t/weekly/withdraw"),
    ("post", "/v1/embed/t/weekly/arena/join"),
    ("get", "/v1/embed/games/00000000-0000-0000-0000-000000000009"),
    ("post", "/v1/embed/games/00000000-0000-0000-0000-000000000009/resign"),
    ("delete", "/v1/embed/sessions/current"),
]


@pytest.mark.parametrize("headers", [{}, {"X-Ocheso-Session": "oche_short"}, {"X-Ocheso-Session": PLAYER},
                                     {"Authorization": f"Bearer {SESSION}"}])
@pytest.mark.parametrize("method,path", SESSION_ROUTES)
def test_embed_actions_need_a_session(monkeypatch, headers, method, path):
    log = install(monkeypatch)
    r = client.request(method.upper(), path, headers=headers)
    assert r.status_code == 401, r.text
    assert r.json()["code"] in ("session_required", "wrong_token")
    assert log == []


def test_a_session_travels_as_its_hash(monkeypatch):
    log = install(monkeypatch, {"embed_call": {"entry": None, "invite_pending": False, "current_game": None,
                                               "next": None}})
    r = client.get("/v1/embed/t/weekly/me", headers={"X-Ocheso-Session": SESSION})
    assert r.status_code == 200 and r.headers["cache-control"] == "private, no-store"
    [body] = payloads(log)
    assert body == {**body, "kind": "emb-me", "session": sha(SESSION), "slug": "weekly"}
    assert not leaked(log, SESSION)


def test_a_player_token_becomes_a_session_by_its_hash(monkeypatch):
    log = install(monkeypatch, {"embed_call": lambda p: {"counted": True} if json.loads(p["p_payload"]).get("phase")
                                else {"session": SESSION, "expires_at": "x",
                                      "player": {"id": "p", "name": "Ama", "kind": "member"},
                                      "scope": {"tournament": "weekly"}}})
    r = client.post("/v1/embed/sessions", json={"player_token": PLAYER, "parent_origin": "https://yoursite.com"},
                    headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    assert r.status_code == 201 and r.json()["session"] == SESSION
    # The database's scope, as it said it: where the frame keeps the session.
    assert r.json()["scope"] == {"tournament": "weekly"}
    # Counted first in a call of its own, so failed attempts still count.
    hit, real = payloads(log)
    assert hit["phase"] == "hit" and real["counted"] is True and "phase" not in real
    assert real["kind"] == "emb-session-member" and real["token"] == sha(PLAYER)
    assert real["parent_origin"] == "https://yoursite.com"
    assert len(real["ip"]) == 64 and "203.0.113.7" not in json.dumps(real)
    assert not leaked(log, PLAYER)


def test_a_page_off_the_list_is_403_origin_not_allowed(monkeypatch):
    def embed_call(params):
        if json.loads(params["p_payload"]).get("phase"):
            return {"counted": True}
        raise APIError({"code": "OC403", "message": "https://copycat.example cannot sign players in to Yoursite tournaments"})

    log = install(monkeypatch, {"embed_call": embed_call})
    r = client.post("/v1/embed/sessions", json={"player_token": PLAYER, "parent_origin": "https://copycat.example"})
    assert r.status_code == 403
    assert r.json() == {"detail": "https://copycat.example cannot sign players in to Yoursite tournaments",
                        "code": "origin_not_allowed"}
    # Counted before it was refused, so a token cannot be tried on page after page for free.
    assert [b.get("phase") for b in payloads(log)] == ["hit", None]


def test_an_app_webview_sends_no_parent_origin_and_gets_a_session(monkeypatch):
    # ?app=1 is top level: no parent page to name. The API passes null on and
    # the database checks a page only when one is given (D3).
    log = install(monkeypatch, {"embed_call": lambda p: {"counted": True} if json.loads(p["p_payload"]).get("phase")
                                else {"session": SESSION, "expires_at": "x",
                                      "player": {"id": "p", "name": "Ama", "kind": "member"},
                                      "scope": {"tournament": None}}})
    r = client.post("/v1/embed/sessions", json={"player_token": PLAYER})
    assert r.status_code == 201 and r.json()["session"] == SESSION
    assert payloads(log)[-1]["parent_origin"] is None


@pytest.mark.parametrize("origin", ["https://a.com/path", "a.com", "javascript:alert(1)", "https://a.com\nx"])
def test_a_parent_origin_is_an_origin(monkeypatch, origin):
    log = install(monkeypatch)
    assert client.post("/v1/embed/sessions", json={"player_token": PLAYER, "parent_origin": origin}).status_code == 422
    assert log == []


@pytest.mark.parametrize("token", [ORG_KEY, SESSION, "ochp_" + "2B" * 24, "ochp_short"])
def test_only_player_tokens_open_member_sessions(monkeypatch, token):
    log = install(monkeypatch)
    r = client.post("/v1/embed/sessions", json={"player_token": token})
    assert r.status_code in (401, 422)
    assert log == []


def test_a_move_is_judged_then_signed_for_the_session(monkeypatch):
    start_fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
    g = {"id": "00000000-0000-0000-0000-000000000009", "status": "live", "white_id": "me", "black_id": "them",
         "turn": "white", "ply": 0, "position": start_fen}
    color = {"mine": "white"}

    def embed_call(params):
        body = json.loads(params["p_payload"])
        if body["kind"] == "emb-game":
            return {"game": g, "tournament": {"game": "chess", "variant": "standard"}, "moves": [],
                    "my_color": color["mine"], "topic": "live:g:" + "0" * 32}
        return {**g, "ply": 1}

    log = install(monkeypatch, {"embed_call": embed_call})
    r = client.post(f"/v1/embed/games/{g['id']}/move", json={"move": "e2e4", "ply": 0},
                    headers={"X-Ocheso-Session": SESSION})
    assert r.status_code == 200, r.text
    read, move = payloads(log)
    assert read["kind"] == "emb-game" and move["kind"] == "emb-move"
    assert move["session"] == sha(SESSION) and move["move"] == "e2e4" and move["san"] == "e4"
    assert move["before"] == start_fen and move["ply"] == 0 and "by" not in move
    # Illegal, or not your move: refused before anything is signed.
    log.clear()
    assert client.post(f"/v1/embed/games/{g['id']}/move", json={"move": "e2e5"},
                       headers={"X-Ocheso-Session": SESSION}).status_code == 422
    g["turn"] = "black"
    assert client.post(f"/v1/embed/games/{g['id']}/move", json={"move": "e7e5"},
                       headers={"X-Ocheso-Session": SESSION}).status_code == 409
    color["mine"] = None  # watching, not playing
    assert client.post(f"/v1/embed/games/{g['id']}/move", json={"move": "e7e5"},
                       headers={"X-Ocheso-Session": SESSION}).status_code == 403
    assert [b["kind"] for b in payloads(log)] == ["emb-game", "emb-game", "emb-game"]


def test_a_game_read_comes_with_its_realtime_topic(monkeypatch):
    install(monkeypatch, {"embed_call": {"game": {"id": "g"}, "moves": [], "my_color": None,
                                         "topic": "live:g:" + "1" * 32}})
    r = client.get("/v1/embed/g/00000000-0000-0000-0000-000000000009", headers={"Origin": "https://partner.example"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "*"
    assert r.json()["realtime"]["topic"] == "live:g:" + "1" * 32 and "topic" not in r.json()


def test_handoff_start_peek_and_redeem(monkeypatch):
    log = install(monkeypatch, {"embed_call": {"status": "pending"}})
    s = "ab" * 32
    h = hashlib.sha256(bytes.fromhex(s)).hexdigest()
    assert client.post("/v1/embed/handoff/start", json={"h": h, "slug": "weekly"}).status_code == 201
    assert client.get(f"/v1/embed/handoff/{h}").json() == {"status": "pending"}
    r = client.post("/v1/embed/handoff/redeem", json={"s": s})
    assert r.status_code == 200 and r.json() == {"status": "pending"}
    hit, start, peek, redeem = payloads(log)
    assert hit["phase"] == "hit" and start["h"] == h and start["slug"] == "weekly"
    assert peek == {**peek, "kind": "emb-handoff-peek", "h": h}
    # S itself goes to the database, which hashes it to find the handoff.
    assert redeem["kind"] == "emb-handoff-redeem" and redeem["s"] == s
    for bad in ({"s": "AB" * 32}, {"s": "ab" * 31}, {"s": h + "0"}):
        assert client.post("/v1/embed/handoff/redeem", json=bad).status_code == 422


# --- public embed reads: any origin, cached ---------------------------------------

BUNDLE = {  # private.emb_bundle
    "v": 1,
    "tournament": {"id": "t1", "slug": "weekly", "title": "Weekly", "game": "chess", "variant": "standard",
                   "format": "swiss", "status": "registration", "tiebreaks": ["buchholz"],
                   "clock": {"base_s": 300, "inc_s": 3}, "entry": {"count": 1, "cap": 16, "full": False, "open": True},
                   "owner_id": "never-leaves", "autopilot_note": "Postponed by 15 minutes.", "rev": 7},
    "org": {"id": "o1", "slug": "yoursite", "name": "Yoursite", "website": "https://yoursite.com", "brand": {},
            "badge": "full", "allowed_origins": ["https://yoursite.com"], "timezone": "Africa/Douala"},
    "roster": [{"participant_id": "e1", "user_id": "a", "name": "Ama", "username": None, "avatar_url": None,
                "country": "CM", "kind": "member", "rating_at_entry": 1500, "seed": None,
                "joined_at": "2026-10-01T00:00:00Z"}],
    "people": [], "results": [], "rounds": [], "live": [],
    "topic": "live:t:0123456789abcdef0123456789abcdef", "rev": 7, "server_now": "2026-10-25T12:00:00Z",
}


def test_the_bundle_is_public_cached_and_shaped(monkeypatch):
    log = install(monkeypatch, {"embed_call": BUNDLE})
    r = client.get("/v1/embed/t/weekly?rev=7", headers={"Origin": "https://partner.example"})
    assert r.status_code == 200, r.text
    assert r.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in r.headers
    assert r.headers["cache-control"] == "public, max-age=5, s-maxage=5, stale-while-revalidate=30"
    out = r.json()
    assert out["v"] == 1 and out["rev"] == 7
    assert out["realtime"]["topic"] == "live:t:0123456789abcdef0123456789abcdef"
    assert out["tournament"]["clock"] == {"base_s": 300, "inc_s": 3}
    assert out["tournament"]["entry"] == {"count": 1, "cap": 16, "full": False, "open": True}
    assert "owner_id" not in out["tournament"] and out["tournament"]["note"] == "Postponed by 15 minutes."
    assert out["org"] == {"slug": "yoursite", "name": "Yoursite", "website": "https://yoursite.com", "brand": {},
                          "badge": "full", "allowed_origins": ["https://yoursite.com"]}
    assert out["standings"]["lines"][0]["player"]["display_name"] == "Ama"
    assert out["hosted_url"] == "https://www.ocheso.com/o/yoursite/weekly"
    [body] = payloads(log)
    assert body["kind"] == "emb-bundle" and body["slug"] == "weekly" and "preview" not in body


def _result(n, board, white, black, status="finished", result="white"):
    return {"game_id": f"g{n}-{board}", "round_number": n, "round_status": "finished" if status == "finished" else "live",
            "board": board, "white_id": white, "black_id": black, "status": status, "result": result,
            "termination": "checkmate" if status == "finished" else None, "tiebreak_of": None, "finished_at": None}


def test_the_bundle_carries_every_round_for_the_bracket(monkeypatch):
    # A knockout of eight, three rounds in: the bracket needs round 1 too.
    people = [{"id": p, "name": p.upper(), "username": None, "avatar_url": None, "country": None, "kind": "member"}
              for p in "abcdefgh"]
    results = [_result(1, b + 1, w, k) for b, (w, k) in enumerate([("a", "b"), ("c", "d"), ("e", "f"), ("g", "h")])]
    results += [_result(2, 1, "a", "c"), _result(2, 2, "e", "g"), _result(3, 1, "a", "e", "live", None)]
    raw = {**BUNDLE, "tournament": {**BUNDLE["tournament"], "format": "knockout", "status": "live"},
           "roster": [], "people": people, "results": results,
           "rounds": [{"number": n, "status": "finished" if n < 3 else "live", "created_at": None, "started_at": None,
                       "finished_at": None} for n in (1, 2, 3)],
           "live": [{"id": "g3-1", "round": 3, "board": 1, "white_id": "a", "black_id": "e", "position": "x",
                     "turn": "white", "ply": 4, "last_move": None, "white_ms": 1, "black_ms": 1,
                     "turn_started_at": None, "topic": None}]}
    install(monkeypatch, {"embed_call": raw})
    out = client.get("/v1/embed/t/weekly").json()
    assert [(r["number"], r["status"], len(r["games"])) for r in out["rounds"]] == [(1, "finished", 4), (2, "finished", 2),
                                                                                   (3, "live", 1)]
    first = out["rounds"][0]["games"][0]
    assert first["result"] == "white"
    # Lean: names and results, never a move list; a player is a name and an id.
    assert set(first) == {"id", "board", "white", "black", "status", "result", "termination", "tiebreak_of"}
    assert first["white"] == {"id": "a", "display_name": "A", "username": None}
    assert "moves" not in json.dumps(out["rounds"])


def test_a_swiss_bundle_keeps_the_current_and_previous_round(monkeypatch):
    # Thirty-nine rounds of a round robin, or of a Swiss: the latest two (D3),
    # older ones are on /rounds; an arena's games stay its latest 100.
    results = [_result(n, 1, "a", "b") for n in range(1, 40)]
    results += [{**_result(1, None, "a", "b"), "game_id": f"arena-{i}", "round_number": None} for i in range(150)]
    for fmt in ("round_robin", "swiss"):
        install(monkeypatch, {"embed_call": {**BUNDLE, "tournament": {**BUNDLE["tournament"], "format": fmt},
                                             "results": results}})
        out = client.get("/v1/embed/t/weekly").json()
        assert [r["number"] for r in out["rounds"] if r["number"] is not None] == [38, 39]
        [arena] = [r for r in out["rounds"] if r["number"] is None]
        assert len(arena["games"]) == 100 and arena["games"][-1]["id"] == "arena-149"


def _big(players: int, rounds: int, fmt: str, live: int = 0) -> dict:
    """A large event as emb-bundle reads it: every name long, every avatar a
    long URL - the heaviest a bundle's people can be."""
    ids = [f"{i:08x}-0000-4000-8000-{i:012x}" for i in range(players)]
    people = [{"id": p, "name": f"Player Number {i:04d}", "username": f"player{i:04d}",
               "avatar_url": "https://lh3.googleusercontent.com/a/ACg8ocK" + "x" * 60 + "=s96-c", "country": "CM",
               "kind": "member"} for i, p in enumerate(ids)]
    size = lambda n: players // 2 if fmt != "knockout" else max(1, players >> n)  # noqa: E731
    results = [{**_result(n, b + 1, ids[(2 * b + n) % players], ids[(2 * b + 1 + n) % players]),
                "game_id": f"{n:04d}{b:04d}-0000-4000-8000-000000000000"}
               for n in range(1, rounds + 1) for b in range(size(n))]
    games = [{"id": f"live-{b}", "round": rounds, "board": b + 1, "white_id": ids[2 * b], "black_id": ids[2 * b + 1],
              "position": "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1", "turn": "black", "ply": 1,
              "last_move": "e2e4", "white_ms": 300000, "black_ms": 300000, "turn_started_at": "2026-10-25T12:00:00Z",
              "topic": "0123456789abcdef0123456789abcdef"} for b in range(live)]
    return {**BUNDLE, "tournament": {**BUNDLE["tournament"], "format": fmt, "status": "live", "max_participants": players,
                                     "games_watchable": True, "participants_visible": True},
            "roster": [{**BUNDLE["roster"][0], "participant_id": p, "user_id": p, **{k: q[k] for k in ("name", "username",
                        "avatar_url", "country")}} for p, q in zip(ids, people)],
            "people": people, "results": results, "live": games}


def test_a_knockout_bundle_keeps_its_bracket_until_it_is_too_big(monkeypatch):
    # A knockout of 2048 holds 2047 games in all: the whole bracket goes in.
    install(monkeypatch, {"embed_call": _big(2048, 11, "knockout")})
    out = client.get("/v1/embed/t/weekly").json()
    assert [r["number"] for r in out["rounds"]] == list(range(1, 12))
    # Of 4096, in round 2: round 1's 2048 games would pass BUNDLE_GAMES, so the
    # bracket starts at round 2 (the view says earlier rounds aren't shown).
    install(monkeypatch, {"embed_call": _big(4096, 2, "knockout")})
    assert [r["number"] for r in client.get("/v1/embed/t/weekly").json()["rounds"]] == [2]
    # The newest round always goes in whole, however big.
    install(monkeypatch, {"embed_call": _big(4096, 1, "knockout")})
    [first] = client.get("/v1/embed/t/weekly").json()["rounds"]
    assert len(first["games"]) == 2048


def test_the_biggest_bundle_stays_far_below_what_a_function_may_answer(monkeypatch):
    # 4096 players, 13 Swiss rounds, the last one in play: 26,624 games, 2048
    # live. Whole, that is about 20 MB; Vercel answers at most 4.5 MB.
    install(monkeypatch, {"embed_call": _big(4096, 13, "swiss", live=2048)})
    r = client.get("/v1/embed/t/weekly")
    assert r.status_code == 200
    assert len(r.content) < 3 * 1024 * 1024, len(r.content)
    out = r.json()
    assert len(out["standings"]["lines"]) == 4096
    assert [(x["number"], len(x["games"])) for x in out["rounds"]] == [(13, 2048)]
    assert len(out["live"]) == 100 and out["live"][0]["board"] == 1 and out["live"][0]["white"]["display_name"]


def test_a_preview_is_for_the_organiser_and_never_cached(monkeypatch):
    token = jwt()
    log = install(monkeypatch, {"embed_call": BUNDLE, "get_tournament": [{"id": "t1", "slug": "weekly"}],
                                "tournament_secrets": [{"tournament_id": "t1"}]})
    r = client.get("/v1/embed/t/weekly?preview=1", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.headers["cache-control"] == "private, no-store"
    # Checked as the caller - the event, then its secrets row (managers only) - then vouched for.
    assert [(bearer == token, name) for _, bearer, name, _ in log] == [
        (True, "get_tournament"), (True, "tournament_secrets"), (False, "embed_call")]
    assert payloads(log)[0]["preview"] is True
    assert client.get("/v1/embed/t/weekly?preview=1").status_code == 401


def test_a_preview_for_someone_who_does_not_manage_it_is_404(monkeypatch):
    log = install(monkeypatch, {"embed_call": BUNDLE, "get_tournament": [{"id": "t1", "slug": "weekly"}],
                                "tournament_secrets": []})
    r = client.get("/v1/embed/t/weekly?preview=1", headers={"Authorization": f"Bearer {jwt()}"})
    assert r.status_code == 404 and not [x for x in log if x[2] == "embed_call"]


def test_public_preflight_from_any_origin():
    r = client.options("/v1/embed/t/weekly", headers={"Origin": "https://partner.example",
                                                       "Access-Control-Request-Method": "GET"})
    assert r.status_code == 204 and r.headers["access-control-allow-origin"] == "*"


def test_session_routes_stay_behind_the_origin_list(monkeypatch):
    install(monkeypatch, {"embed_call": {}})
    r = client.get("/v1/embed/t/weekly/me", headers={"X-Ocheso-Session": SESSION, "Origin": "https://partner.example"})
    assert r.headers.get("access-control-allow-origin") != "*"
    pre = client.options("/v1/embed/t/weekly/me", headers={"Origin": "https://partner.example",
                                                           "Access-Control-Request-Method": "GET"})
    assert pre.headers.get("access-control-allow-origin") is None
    ok = client.options("/v1/embed/t/weekly/me", headers={"Origin": "https://www.ocheso.com",
                                                          "Access-Control-Request-Method": "GET",
                                                          "Access-Control-Request-Headers": "x-ocheso-session"})
    assert ok.headers["access-control-allow-origin"] == "https://www.ocheso.com"
    assert "x-ocheso-session" in ok.headers["access-control-allow-headers"].lower()


def test_platform_preflight_allows_idempotency_key():
    ok = client.options("/v1/platform/tournaments", headers={"Origin": "https://www.ocheso.com",
                                                             "Access-Control-Request-Method": "POST",
                                                             "Access-Control-Request-Headers": "idempotency-key"})
    assert "idempotency-key" in ok.headers["access-control-allow-headers"].lower()


@pytest.mark.parametrize("origins,policy", [
    ([], "*"),
    (["https://yoursite.com", "https://*.yoursite.com"], "'self' https://yoursite.com https://*.yoursite.com"),
    (["https://yoursite.com; script-src *"], "'self'"),     # never written into a header unchecked
])
def test_policy(monkeypatch, origins, policy):
    log = install(monkeypatch, {"get_embed_policy": origins})
    for q, params in (("o=yoursite", {"p_tournament": None, "p_org": "yoursite", "p_game": None}),
                      ("t=weekly", {"p_tournament": "weekly", "p_org": None, "p_game": None}),
                      ("g=00000000-0000-0000-0000-000000000009",
                       {"p_tournament": None, "p_org": None, "p_game": "00000000-0000-0000-0000-000000000009"})):
        r = client.get(f"/v1/embed/policy?{q}", headers={"Origin": "https://partner.example"})
        assert r.json() == {"frame_ancestors": policy}, q
        assert "s-maxage=60" in r.headers["cache-control"] and r.headers["access-control-allow-origin"] == "*"
        assert log[-1][2:] == ("get_embed_policy", params)
    assert client.get("/v1/embed/policy").status_code == 400
    assert client.get("/v1/embed/policy?t=a&o=b").status_code == 400


def test_policy_for_nothing_is_404(monkeypatch):
    install(monkeypatch, {"get_embed_policy": None})
    assert client.get("/v1/embed/policy?t=nope").status_code == 404


def test_ping_is_text_plain_and_answers_any_origin(monkeypatch):
    log = install(monkeypatch, {"embed_call": None})
    body = json.dumps({"t": "weekly", "origin": "https://YourSite.com", "view": "standings", "path": "/club"})
    r = client.post("/v1/embed/ping", content=body, headers={"Content-Type": "text/plain",
                                                             "Origin": "https://yoursite.com"})
    assert r.status_code == 204 and r.headers["access-control-allow-origin"] == "*"
    [sent] = payloads(log)
    assert sent["kind"] == "emb-ping" and sent["origin"] == "https://yoursite.com" and sent["t"] == "weekly"
    assert "o" not in sent and "s" not in sent  # the database tells t from o by which key is present
    for bad in ("not json", json.dumps({"origin": "https://a.com"}), json.dumps({"t": "w", "o": "x", "origin": "https://a.com"}),
                json.dumps({"s": "friday", "origin": "https://a.com"}), json.dumps({"t": "w", "s": "x", "origin": "https://a.com"}),
                json.dumps({"t": "w", "origin": "javascript:x"}), json.dumps({"t": "w", "origin": "https://a.com", "path": "club"}),
                "x" * 3000):
        assert client.post("/v1/embed/ping", content=bad, headers={"Content-Type": "text/plain"}).status_code in (400, 413), bad


def test_the_loaders_beacon_pings_for_a_series(monkeypatch):
    log = install(monkeypatch, {"embed_call": None})
    for path in ("", None, "   "):
        body = {"s": "friday-blitz", "o": "yoursite", "origin": "https://yoursite.com", "view": "series"}
        if path is not None:
            body["path"] = path
        r = client.post("/v1/embed/ping", content=json.dumps(body), headers={"Content-Type": "text/plain"})
        assert r.status_code == 204, (path, r.text)
        sent = payloads(log)[-1]
        assert sent["kind"] == "emb-ping" and sent["s"] == "friday-blitz" and sent["o"] == "yoursite" and "t" not in sent
        assert sent["path"] is None  # missing or empty: no path, never ""


# --- refusals ---------------------------------------------------------------------

def test_throttles_answer_429_with_a_reason_and_retry_after():
    http = fail(APIError({"code": "OC429", "message": "too many player tokens this minute"}))
    assert http.status_code == 429 and http.detail == "too many player tokens this minute"
    assert http.code == "rate_limited" and http.headers == {"Retry-After": "60"}


def test_a_throttled_route_says_429(monkeypatch):
    install(monkeypatch, {"org_call": APIError({"code": "OC429", "message": "too many player tokens this minute"})})
    r = client.post("/v1/platform/player-tokens", headers={"Authorization": f"Bearer {ORG_KEY}"},
                    json={"external_id": "u1", "name": "Ama"})
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert r.json() == {"detail": "too many player tokens this minute", "code": "rate_limited"}


def test_an_expired_session_is_401_so_the_frame_asks_again(monkeypatch):
    install(monkeypatch, {"embed_call": APIError({"code": "OC401", "message": "that session has expired"})})
    r = client.get("/v1/embed/t/weekly/me", headers={"X-Ocheso-Session": SESSION})
    assert r.status_code == 401 and r.json()["code"] == "session_expired"


def test_signing_off_is_503_not_a_crash(monkeypatch):
    install(monkeypatch, secret="")
    r = client.get("/v1/platform/tournaments", headers={"Authorization": f"Bearer {ORG_KEY}"})
    assert r.status_code == 503 and r.json()["code"] == "unavailable"


# --- the tick ---------------------------------------------------------------------

def _tick(ts=None):
    return json.dumps({"kind": "tick", "ts": int(time.time()) if ts is None else ts, "nonce": "n"}).encode()


def _sign(body, secret=SECRET):
    key = hmac.new(secret.encode(), b"ocheso:v1:tick", hashlib.sha256).hexdigest()
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def test_a_signed_tick_runs_the_autopilot(monkeypatch):
    import autopilot

    install(monkeypatch)
    ran = []
    monkeypatch.setattr(autopilot, "run_tick", lambda: ran.append(1) or {"ok": True, "leased": 0})
    body = _tick()
    r = client.post("/v1/internal/tick", content=body, headers={"X-Ocheso-Tick": _sign(body)})
    assert r.status_code == 200 and r.json()["ok"] and ran == [1]


@pytest.mark.parametrize("why", ["unsigned", "wrong key", "stale", "re-serialised", "too big"])
def test_bad_ticks_are_refused_and_nothing_runs(monkeypatch, why):
    import autopilot

    install(monkeypatch)
    monkeypatch.setattr(autopilot, "run_tick", lambda: pytest.fail("ran"))
    body = _tick(ts=int(time.time()) - 120) if why == "stale" else _tick()
    headers = {} if why == "unsigned" else {"X-Ocheso-Tick": _sign(body, "other" if why == "wrong key" else SECRET)}
    if why == "re-serialised":
        body = json.dumps(json.loads(body), indent=2).encode()
    if why == "too big":
        body = body[:-1] + b',"pad":"' + b"x" * 5000 + b'"}'
        headers = {"X-Ocheso-Tick": _sign(body)}
    r = client.post("/v1/internal/tick", content=body, headers=headers)
    assert r.status_code in (401, 413) and r.json()["code"] == "bad_tick"


# --- /v1/me claims invites ---------------------------------------------------------

PROFILE = {"id": "u1", "username": "ama", "display_name": "Ama", "chess_rating": 1500, "checkers_rating": 1200,
           "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}


def test_me_claims_invites_first(monkeypatch):
    log = install(monkeypatch, {"claim_my_invites": [{"slug": "weekly", "title": "Weekly Blitz"}], "me": PROFILE})
    r = client.get("/v1/me", headers={"Authorization": f"Bearer {jwt()}"})
    assert r.status_code == 200
    assert r.json()["claimed"] == [{"slug": "weekly", "title": "Weekly Blitz", "starts_at": None, "org": None}]
    assert [fn for _, _, fn, _ in log] == ["claim_my_invites", "me"]


@pytest.mark.parametrize("claim", [
    APIError({"code": "PGRST202", "message": "Could not find the function public.claim_my_invites"}),
    APIError({"code": "XX000", "message": "boom"}),
    3,
    None,
])
def test_me_still_answers_when_claiming_cannot(monkeypatch, claim):
    install(monkeypatch, {"claim_my_invites": claim, "me": PROFILE})
    r = client.get("/v1/me", headers={"Authorization": f"Bearer {jwt()}"})
    assert r.status_code == 200 and r.json()["claimed"] == [] and r.json()["username"] == "ama"


# --- errors carry a code -------------------------------------------------------------

def test_every_error_has_detail_and_code():
    for r, code in ((client.get("/v1/me"), "unauthorized"),
                    (client.get("/v1/nowhere"), "not_found"),
                    (client.post("/v1/tournaments", json={"title": "x"}, headers={"Authorization": "Bearer t"}),
                     "invalid")):
        body = r.json()
        assert set(body) == {"detail", "code"} and body["code"] == code


def test_arena_join_picks_an_opponent_and_signs_the_pairing(monkeypatch):
    def embed_call(params):
        body = json.loads(params["p_payload"])
        if body["kind"] == "emb-arena-join":
            return {"status": "queued", "tournament": "t1", "me": "me",
                    "queue": [{"user_id": "them", "since": "2026-10-25T12:00:00Z"},
                              {"user_id": "me", "since": "2026-10-25T12:00:05Z"}],
                    "seeds": [{"user_id": "me", "rating": 1500}, {"user_id": "them", "rating": 1450}],
                    "results": []}
        return [{"id": "g1", "white_id": "me", "black_id": "them", "status": "live"}]

    log = install(monkeypatch, {"embed_call": embed_call,
                                "get_tournament": [{"id": "t1", "slug": "arena", "game": "chess",
                                                    "variant": "standard", "format": "arena"}]})
    r = client.post("/v1/embed/t/arena/arena/join", headers={"X-Ocheso-Session": SESSION})
    assert r.status_code == 200 and r.json()["status"] == "paired" and r.json()["game"]["id"] == "g1"
    join, pairing = payloads(log)
    assert pairing["kind"] == "emb-arena-pairings" and pairing["tournament"] == "t1"
    [g] = pairing["games"]
    assert {g["white"], g["black"]} == {"me", "them"} and g["position"].startswith("rnbqkbnr")


def test_arena_join_alone_waits(monkeypatch):
    install(monkeypatch, {"embed_call": {"status": "queued", "tournament": "t1", "me": "me",
                                         "queue": [{"user_id": "me", "since": "2026-10-25T12:00:05Z"}],
                                         "seeds": [], "results": []},
                          "get_tournament": [{"id": "t1", "game": "chess", "variant": "standard"}]})
    r = client.post("/v1/embed/t/arena/arena/join", headers={"X-Ocheso-Session": SESSION})
    assert r.json() == {"status": "waiting"}


# --- review fixes ----------------------------------------------------------------

def test_an_embed_join_is_counted_in_a_call_of_its_own_first(monkeypatch):
    # A wrong entry code rolls the join's transaction back, and a hit counted
    # inside it with it: the attempt is counted first, then the join is made.
    log = install(monkeypatch, {"embed_call": lambda p: ({"counted": True} if json.loads(p["p_payload"]).get("phase") == "hit"
                                                         else {"status": "approved"})})
    r = client.post("/v1/embed/t/weekly/join", headers={"X-Ocheso-Session": SESSION}, json={"code": "WRONG1"})
    assert r.status_code == 200, r.text
    hit, join = payloads(log)
    assert hit["kind"] == join["kind"] == "emb-join" and hit["phase"] == "hit" and "counted" not in hit
    assert join["counted"] is True and "phase" not in join and join["code"] == "WRONG1"
    assert hit["session"] == join["session"] == sha(SESSION) and not leaked(log, SESSION)


@pytest.mark.parametrize("answer,status", [({"erased": True, "profile_id": "p1"}, 204), ({"erased": False}, 404)])
def test_erasure_says_when_it_found_nobody(monkeypatch, answer, status):
    # A platform that is told 204 believes the person is gone; a miss must show.
    log = install(monkeypatch, {"org_call": answer})
    r = client.delete("/v1/platform/players/alice%20", headers={"Authorization": f"Bearer {ORG_KEY}"})
    assert r.status_code == status, r.text
    if status == 404:
        assert r.json()["code"] == "not_found"
    # Sent as given: the database trims it the way it trimmed it when the player was made.
    [body] = payloads(log)
    assert body["kind"] == "org-player-erase" and body["external_id"] == "alice "


def _bootstrap(monkeypatch, instance_starts: str, chosen: str):
    org = {"id": "o1", "slug": "yoursite", "name": "Yoursite", "timezone": "Africa/Douala"}
    instance = {"id": "t1", "slug": "weekly-blitz", "title": "Weekly Blitz", "status": "registration",
                "starts_at": instance_starts, "series_id": "s1"}

    def tournaments(ops):
        for op, args, _ in ops:
            if op == "update":
                return [{**instance, **args[0]}]
        return [instance]

    log = install(monkeypatch, {"org_members": [], "create_organization": org,
                                "create_series": {"id": "s1", "slug": "weekly-blitz"}, "tournaments": tournaments})
    body = {"org": {"name": "Yoursite", "timezone": "Africa/Douala"},
            "tournament": {"title": "Weekly Blitz", "game": "chess", "variant": "standard", "format": "arena",
                           "clock_base_s": 180, "clock_increment_s": 2, "arena_minutes": 60, "starts_at": chosen},
            "series": {"weekday": 5, "local_time": "19:00"}}
    r = client.post("/v1/orgs/bootstrap", headers={"Authorization": f"Bearer {jwt()}"}, json=body)
    assert r.status_code == 201, r.text
    return r.json(), log


def test_bootstrap_with_a_series_keeps_the_date_the_organiser_chose(monkeypatch):
    # "Today 19:00" on a Sunday, with the weekly-on-Friday template: the first
    # event is on Sunday, and the series takes over from the next instance.
    out, log = _bootstrap(monkeypatch, instance_starts="2026-10-30T18:00:00+00:00", chosen="2026-10-25T18:00:00Z")
    assert out["tournament"]["starts_at"].startswith("2026-10-25T18:00:00")
    template = next(p for kind, _, fn, p in log if fn == "create_series")["p_template"]
    assert "starts_at" not in template  # the series' rhythm is weekday + local_time


def test_bootstrap_with_a_series_on_its_own_day_changes_nothing(monkeypatch):
    out, log = _bootstrap(monkeypatch, instance_starts="2026-10-30T18:00:00+00:00", chosen="2026-10-30T18:00:00Z")
    assert out["tournament"]["starts_at"] == "2026-10-30T18:00:00+00:00"
    assert [fn for kind, _, fn, _ in log if kind == "table"].count("tournaments") == 1  # read, no update


def test_a_team_invitation_can_be_withdrawn(monkeypatch):
    log = install(monkeypatch, {"organizations": [{"id": "o1", "slug": "yoursite"}], "revoke_org_invite": {"status": "revoked"}})
    inv = "6f1c0000-0000-0000-0000-000000000001"
    r = client.delete(f"/v1/orgs/yoursite/invites/{inv}", headers={"Authorization": f"Bearer {jwt()}"})
    assert r.status_code == 204, r.text
    assert [p for kind, _, fn, p in log if fn == "revoke_org_invite"] == [{"p_invite": inv}]
