"""
The API's own behaviour - the parts that do not need a database.

What the database allows is proven separately, as real Postgres roles, in
db/test/test_rls.py. These cover what sits in front of it: that nothing reaches
the database without a token where one is required, that bodies cannot carry
fields the caller may not set, that refusals become honest statuses without
leaking internals, and that the removed routes are really gone.

The tests this replaced asserted `status_code in [200, 400, 500]`, which passes
whether an endpoint works or crashes.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient
from postgrest import APIError

from config import Settings
from db import fail
from main import app
from schemas.tournament import TournamentCreate

client = TestClient(app)
AUTH = {"Authorization": "Bearer not-a-real-token"}

GOOD = {
    "title": "Saturday Rapid",
    "game": "chess",
    "variant": "standard",
    "format": "swiss",
    "clock_base_s": 600,
    "clock_increment_s": 5,
    "starts_at": "2026-11-01T14:00:00Z",
    "rounds_count": 5,
}


def _jwt(role: str) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'role': role, 'iss': 'supabase'})}.signature"


# --- the key ---------------------------------------------------------------

@pytest.mark.parametrize("key", [_jwt("service_role"), "sb_secret_abc123"])
def test_refuses_to_start_with_a_privileged_key(key):
    # With a service-role key, every anonymous request would bypass RLS and
    # every guarantee in the schema would stop applying, silently.
    with pytest.raises(ValueError, match="service-role"):
        Settings(SUPABASE_URL="https://x.supabase.co", SUPABASE_ANON_KEY=key)


@pytest.mark.parametrize("key", [_jwt("anon"), "sb_publishable_abc123"])
def test_accepts_a_public_key(key):
    assert Settings(SUPABASE_URL="https://x.supabase.co", SUPABASE_ANON_KEY=key).SUPABASE_ANON_KEY == key


def test_a_secret_key_is_refused_even_beside_a_public_one():
    # Unused today is one refactor from used tomorrow.
    with pytest.raises(ValueError):
        Settings(
            SUPABASE_URL="https://x.supabase.co",
            SUPABASE_ANON_KEY="sb_publishable_abc",
            SUPABASE_KEY=_jwt("service_role"),
        )


def test_the_old_variable_name_still_works():
    s = Settings(SUPABASE_URL="https://x.supabase.co", SUPABASE_ANON_KEY="", SUPABASE_KEY="sb_publishable_old")
    assert s.SUPABASE_ANON_KEY == "sb_publishable_old"


# --- tokens ----------------------------------------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/v1/tournaments/mine"),
        ("post", "/v1/tournaments"),
        ("patch", "/v1/tournaments/x"),
        ("delete", "/v1/tournaments/x"),
        ("post", "/v1/tournaments/x/publish"),
        ("get", "/v1/tournaments/x/access"),
        ("post", "/v1/tournaments/x/join"),
        ("post", "/v1/tournaments/x/withdraw"),
        ("post", "/v1/participants/x/approve"),
        ("delete", "/v1/participants/x"),
        ("get", "/v1/tournaments/x/staff"),
        ("get", "/v1/me"),
        ("patch", "/v1/me"),
    ],
)
def test_writes_and_private_reads_need_a_token(method, path):
    # 401 before any request is sent - not a request made as anon that the
    # database then happens to refuse.
    kwargs = {"json": {}} if method in ("post", "patch", "put") else {}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 401


def test_a_malformed_authorization_header_is_refused():
    assert client.get("/v1/me", headers={"Authorization": "Token abc"}).status_code == 401


# --- what a body may carry -------------------------------------------------

@pytest.mark.parametrize(
    "extra",
    [{"owner_id": "00000000-0000-0000-0000-000000000000"}, {"status": "live"}, {"id": "x"}],
)
def test_create_refuses_fields_the_caller_may_not_set(extra):
    response = client.post("/v1/tournaments", json={**GOOD, **extra}, headers=AUTH)
    assert response.status_code == 422
    assert list(extra)[0] in response.text


@pytest.mark.parametrize(
    "change,why",
    [
        ({"variant": "brazilian"}, "chess with a checkers variant"),
        ({"game": "checkers", "variant": "standard"}, "checkers with the chess variant"),
        ({"format": "arena", "rounds_count": None}, "an arena with no duration"),
        ({"requires_code": True}, "a code-only event with no code"),
        ({"entry_code": "LIVE42"}, "a code on an event that does not require one - stored and ignored"),
        ({"format": "swiss", "rounds_count": None}, "a Swiss event with no round count"),
        ({"format": "round_robin"}, "a round robin with an invented round count"),
        ({"format": "swiss", "arena_minutes": 60}, "a Swiss event with an arena duration"),
        ({"clock_base_s": 5}, "a five-second game"),
    ],
)
def test_create_refuses_incoherent_tournaments(change, why):
    assert client.post("/v1/tournaments", json={**GOOD, **change}, headers=AUTH).status_code == 422, why


@pytest.mark.parametrize(
    "change",
    [
        {"format": "round_robin", "rounds_count": None},
        {"format": "knockout", "rounds_count": None},
        {"format": "arena", "rounds_count": None, "arena_minutes": 60},
        {"requires_code": True, "entry_code": "LIVE42"},
    ],
)
def test_create_accepts_each_format_shape(change):
    # The validator, not the route: a valid body would go on to call Supabase.
    body = {k: v for k, v in {**GOOD, **change}.items() if v is not None}
    TournamentCreate(**body)


def test_update_cannot_change_what_is_being_played():
    # Changing the game after people entered would change the event they entered.
    for field in ("game", "variant", "format", "owner_id", "status"):
        assert client.patch("/v1/tournaments/x", json={field: "x"}, headers=AUTH).status_code == 422, field


@pytest.mark.parametrize("extra", [{"user_id": "x"}, {"status": "approved"}])
def test_join_takes_neither_identity_nor_approval_from_the_body(extra):
    # The old endpoint took both, so anyone could join as anyone and approve
    # themselves.
    assert client.post("/v1/tournaments/x/join", json=extra, headers=AUTH).status_code == 422


@pytest.mark.parametrize("field", ["chess_rating", "checkers_rating"])
def test_a_profile_update_cannot_set_a_rating(field):
    assert client.patch("/v1/me", json={field: 2800}, headers=AUTH).status_code == 422


# --- refusals become honest statuses ---------------------------------------

@pytest.mark.parametrize(
    "code,status",
    [
        ("P0002", 404),
        ("PGRST116", 404),
        ("23514", 409),
        ("23505", 409),
        ("42501", 403),
        ("28000", 403),
        ("PGRST301", 401),
        ("22P02", 400),
    ],
)
def test_database_codes_map_to_their_meaning(code, status):
    assert fail(APIError({"code": code, "message": "m"})).status_code == status


def test_our_own_sentences_pass_through():
    error = APIError({"code": "23514", "message": "this tournament is full"})
    assert fail(error).detail == "this tournament is full"


@pytest.mark.parametrize(
    "code,internal",
    [
        ("42P01", 'relation "tournament_secrets" does not exist'),
        ("42501", "permission denied for column owner_id"),
        ("XX000", "could not open file base/16384/2619"),
    ],
)
def test_postgres_internals_do_not_reach_the_caller(code, internal):
    # The old API returned str(e), which is how a table name and a schema cache
    # error reached a browser.
    detail = fail(APIError({"code": code, "message": internal})).detail
    assert internal not in detail


# --- what is gone ----------------------------------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/supabase/query/profiles"),
        ("get", "/supabase/test-connection"),
        ("post", "/auth/signin"),
        ("post", "/auth/signup"),
        ("post", "/functions/v1/send-invite"),
        ("get", "/rest/v1/tournaments"),
    ],
)
def test_removed_routes_are_gone(method, path):
    assert getattr(client, method)(path).status_code in (404, 405)


# --- origins ---------------------------------------------------------------

def _preflight(origin):
    return client.options(
        "/v1/tournaments",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )


def test_the_site_may_call():
    assert _preflight("https://www.ocheso.com").headers.get("access-control-allow-origin") == "https://www.ocheso.com"


def test_other_origins_may_not():
    assert "access-control-allow-origin" not in _preflight("https://evil.example").headers


@pytest.mark.parametrize("key,sender,mail", [("", "", "off"), ("re_test", "", "off"), ("re_test", "Ocheso <a@b.co>", "on")])
def test_health_claims_only_what_it_checks(monkeypatch, key, sender, mail):
    # `mail` says whether this process can send - both Resend settings - and
    # nothing about whether anything was sent. Still no claim about the database.
    from config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", key)
    monkeypatch.setattr(settings, "MAIL_FROM", sender)
    assert client.get("/health").json() == {"ok": True, "service": "ocheso-api", "mail": mail}


def test_rows_takes_a_single_row_function_result():
    # PostgREST returns a function's single row as an object. Listing a dict
    # yields its keys, which crashed /v1/me for every signed-in user.
    from types import SimpleNamespace

    from db import rows

    assert rows(SimpleNamespace(data={"id": "u1", "username": "joel"})) == [{"id": "u1", "username": "joel"}]
    assert rows(SimpleNamespace(data=[{"id": "u1"}])) == [{"id": "u1"}]
    assert rows(SimpleNamespace(data=None)) == []


# --- Ocheso for Platforms on the existing routes --------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/v1/orgs"),
        ("post", "/v1/orgs"),
        ("post", "/v1/orgs/bootstrap"),
        ("get", "/v1/orgs/yoursite/keys"),
        ("post", "/v1/orgs/yoursite/keys"),
        ("post", "/v1/tournaments/x/invites"),
        ("get", "/v1/tournaments/x/invites"),
        ("get", "/v1/tournaments/x/autopilot"),
        ("post", "/v1/tournaments/x/autopilot/pause"),
        ("post", "/v1/tournaments/x/autopilot/start-now"),
        ("get", "/v1/me/invites"),
        ("post", "/v1/invites/by-token/0123456789abcdef0123456789abcdef/accept"),
        ("get", "/v1/me/embed-sessions"),
    ],
)
def test_platform_console_routes_need_a_token(method, path):
    kwargs = {"json": {}} if method == "post" else {}
    assert getattr(client, method)(path, **kwargs).status_code == 401


def _created(monkeypatch, body):
    from fakedb import install

    row = {**GOOD, "id": "t1", "slug": "saturday-rapid", "owner_id": "u1", "tiebreaks": ["buchholz"],
           "is_listed": True, "participants_visible": True, "games_watchable": True, "requires_code": False,
           "auto_approve": True, "status": "draft", "created_at": "2026-10-25T00:00:00Z",
           "updated_at": "2026-10-25T00:00:00Z", "org_id": "o1", "identity_mode": "any", "rated": False,
           "autopilot": True, "language": "fr", "autopilot_note": None}
    inserted = []

    def tournaments(ops):
        inserted.extend(args[0] for op, args, _ in ops if op == "insert")
        return [row]

    log = install(monkeypatch, {"organizations": [{"id": "o1", "slug": "yoursite"}], "tournaments": tournaments})
    return client.post("/v1/tournaments", json=body, headers=AUTH), log, inserted


def test_create_for_an_organisation_by_slug(monkeypatch):
    r, log, inserted = _created(monkeypatch, {**GOOD, "org": "yoursite", "identity_mode": "any", "autopilot": True,
                                              "language": "fr"})
    assert r.status_code == 201, r.text
    assert r.json()["org_id"] == "o1" and r.json()["identity_mode"] == "any"
    assert [name for _, _, name, _ in log] == ["organizations", "tournaments"]
    # By id, never the slug; and unrated unless the organiser asked (A9).
    [data] = inserted
    assert data["org_id"] == "o1" and "org" not in data and data["rated"] is False and data["autopilot"] is True


def test_a_personal_tournament_keeps_the_rated_default(monkeypatch):
    r, _, inserted = _created(monkeypatch, GOOD)
    assert r.status_code == 201 and "rated" not in inserted[0] and "org_id" not in inserted[0]


def test_platform_users_need_an_organisation():
    assert client.post("/v1/tournaments", json={**GOOD, "identity_mode": "platform"}, headers=AUTH).status_code == 422


def test_update_takes_the_autopilot_fields_but_not_the_system_ones():
    for field, value in (("autopilot_note", "x"), ("org_id", "o2"), ("embed_rev", 3), ("series_id", "s")):
        assert client.patch("/v1/tournaments/x", json={field: value}, headers=AUTH).status_code == 422, field
    from schemas.tournament import TournamentUpdate

    TournamentUpdate(autopilot=True, min_players=4, short_field="wait", round_break_s=0, language="both",
                     identity_mode="platform", rated=True, invite_only=True, org_listed=False)


def test_entries_claimed_from_email_or_made_by_a_platform_read_back():
    from schemas.participant import ParticipantOut

    for via in ("email", "platform"):
        ParticipantOut(id="p", tournament_id="t", user_id="u", status="approved", joined_via=via,
                       created_at="2026-10-25T00:00:00Z")


def test_a_refusal_keeps_its_detail_and_gains_a_code():
    http = fail(APIError({"code": "23514", "message": "this tournament is full"}))
    assert (http.status_code, http.detail, http.code) == (409, "this tournament is full", "conflict")
