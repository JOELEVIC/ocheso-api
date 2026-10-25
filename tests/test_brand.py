"""
The organisation models agree with the database's checks (spec C1).

private.brand_ok, private.origins_ok and organizations' CHECKs in
db/schema.sql are the guard; core/schemas/org.py repeats them so a bad brand
gets a 422 naming the field instead of a CHECK violation. Each case below says
what the SQL rule decides, and the model must decide the same. The BRANDS and
ORIGINS tables were run through the SQL functions themselves on a throwaway
local database (2026-10-25) and agreed case for case.

One deliberate difference: origins are normalised (trimmed, lower-cased, a
trailing slash dropped) before they are checked, so "https://Yoursite.com/"
is stored as "https://yoursite.com" rather than refused.
"""

import pytest
from pydantic import ValidationError

from schemas.org import Brand, MemberInvite, OrgCreate, OrgUpdate, WebhookCreate, check_origins, slug_ok
from schemas.tournament import TournamentCreate

FULL = {
    "v": 1, "name": "Yoursite", "logo_url": "https://cdn.yoursite.com/logo.png",
    "logo_dark_url": "https://cdn.yoursite.com/logo-dark.svg",
    "colors": {"primary": "#2f55e0", "accent": "#FF5500", "surface_2": "#f5f7fa"},
    "font": "inter", "radius": 12, "theme": "auto", "board": "wood", "locale": "both", "badge": False,
}

# (brand, what private.brand_ok says)
BRANDS = [
    ({}, True),
    (FULL, True),
    ({"radius": 0}, True),
    ({"radius": 24}, True),
    ({"radius": 12.5}, True),
    ({"v": 2.5}, True),
    ({"name": "x" * 80}, True),
    ({"colors": {f"c{i}": "#000000" for i in range(16)}}, True),
    ({"colors": {"a" + "b" * 23: "#000000"}}, True),
    ({"logo_url": "https://x.com/" + "a" * 486}, True),
    ({"badge": True}, True),
    # refused
    ({"css": "body{}"}, False),
    ({"v": "1"}, False),
    ({"name": ""}, False),
    ({"name": "x" * 81}, False),
    ({"name": 5}, False),
    ({"logo_url": "http://x.com/logo.png"}, False),
    ({"logo_url": "https://x.com/a\"b.png"}, False),
    ({"logo_url": "https://x.com/a'b.png"}, False),
    ({"logo_url": "https://x.com/a(b).png"}, False),
    ({"logo_url": "https://x.com/a b.png"}, False),
    ({"logo_url": "https://x.com/a<b>.png"}, False),
    ({"logo_url": "https://x.com/a\\b.png"}, False),
    ({"logo_url": "https://x.com/" + "a" * 487}, False),
    ({"logo_url": 7}, False),
    ({"colors": "#2f55e0"}, False),
    ({"colors": {"Primary": "#2f55e0"}}, False),
    ({"colors": {"1st": "#2f55e0"}}, False),
    ({"colors": {"a" + "b" * 24: "#000000"}}, False),
    ({"colors": {"primary": "#fff"}}, False),
    ({"colors": {"primary": "red"}}, False),
    ({"colors": {"primary": "#gggggg"}}, False),
    ({"colors": {"primary": 0x2f55e0}}, False),
    ({"colors": {f"c{i}": "#000000" for i in range(17)}}, False),
    ({"font": "comic-sans"}, False),
    ({"radius": -1}, False),
    ({"radius": 25}, False),
    ({"radius": "12"}, False),
    ({"radius": True}, False),
    ({"theme": "blue"}, False),
    ({"board": "marble"}, False),
    ({"locale": "de"}, False),
    ({"badge": "false"}, False),
    ({"badge": 0}, False),
]

# (origins as stored, what private.origins_ok says)
ORIGINS = [
    ([], True),
    (["https://yoursite.com"], True),
    (["https://www.yoursite.com", "https://app.yoursite.com:8443"], True),
    (["https://*.yoursite.com"], True),
    (["http://localhost:3000", "http://127.0.0.1"], True),
    ([f"https://s{i}.example.com" for i in range(50)], True),
    (["https://*.com"], False),
    (["https://*.*.example.com"], False),
    (["*"], False),
    (["http://yoursite.com"], False),
    (["http://localhost.evil.com"], False),
    (["https://yoursite.com/path"], False),
    (["https://yoursite..com"], False),
    (["https://yoursite.com:123456"], False),
    (["https://*.yoursite.com:443"], False),
    (["https://" + "a" * 190 + ".com"], False),
    ([f"https://s{i}.example.com" for i in range(51)], False),
]


@pytest.mark.parametrize("brand,ok", BRANDS)
def test_brand_matches_brand_ok(brand, ok):
    if ok:
        Brand.model_validate(brand)
    else:
        with pytest.raises(ValidationError):
            Brand.model_validate(brand)


def test_brand_serialises_the_way_jsonb_prints():
    # octet_length(brand::text): jsonb's text form puts ", " and ": " between
    # items and keeps non-ASCII as UTF-8 - json.dumps' defaults.
    b = Brand.model_validate({"name": "Échecs Douala", "radius": 8})
    assert b.as_json() == '{"name": "Échecs Douala", "radius": 8}'


@pytest.mark.parametrize("origins,ok", ORIGINS)
def test_origins_match_origins_ok(origins, ok):
    if ok:
        assert check_origins(origins) == origins
    else:
        with pytest.raises(ValueError):
            check_origins(origins)


def test_origins_are_normalised_before_they_are_checked():
    assert check_origins([" https://YourSite.com/ "]) == ["https://yoursite.com"]


@pytest.mark.parametrize("slug,ok", [
    ("abc", True), ("my-club", True), ("a1-b2-c3", True), ("a" * 40, True),
    ("ab", False), ("a" * 41, False), ("My-Club", False), ("-abc", False), ("abc-", False), ("a--b", False),
    ("a_b", False), ("abc\n", False),
    *[(w, False) for w in ("www", "api", "embed", "admin", "app", "studio", "platforms", "developers")],
])
def test_slugs(slug, ok):
    assert slug_ok(slug) is ok
    if ok:
        OrgCreate(name="Yoursite", slug=slug)
    else:
        with pytest.raises(ValidationError):
            OrgCreate(name="Yoursite", slug=slug)


@pytest.mark.parametrize("field,value,ok", [
    ("name", "Yo", True), ("name", "Y", False), ("name", " Y ", False), ("name", "x" * 81, False),
    ("website", "https://yoursite.com", True), ("website", "http://yoursite.com", False),
    ("website", "https://yoursite.com/a b", False), ("website", "https://x.com/" + "a" * 290, False),
    ("timezone", "Africa/Douala", True), ("timezone", "Europe/Paris", True), ("timezone", "UTC", True),
    ("timezone", "Mars/Olympus_Mons", False),
])
def test_org_fields(field, value, ok):
    body = {"name": "Yoursite", field: value}
    if ok:
        OrgCreate(**body)
    else:
        with pytest.raises(ValidationError):
            OrgCreate(**body)


@pytest.mark.parametrize("email,ok", [
    ("team@yoursite.com", True), (" Team@YourSite.com ", True), ("a@b.co", True),
    ("a@b.c", False), ("a@b", False), ("a b@c.de", False), ("<a@b.co>", False), ("a@b.co;", False),
    ("a,b@c.de", False), ('"a"@b.co', False),
])
def test_support_email(email, ok):
    if ok:
        assert OrgUpdate(support_email=email).support_email == email.strip().lower()
    else:
        with pytest.raises(ValidationError):
            OrgUpdate(support_email=email)


def test_org_bodies_are_strict():
    for model, body in ((OrgCreate, {"name": "Yo", "plan": "federation"}), (OrgUpdate, {"status": "active"}),
                        (OrgUpdate, {"plan": "club"}), (OrgCreate, {"name": "Yo", "created_by": "x"})):
        with pytest.raises(ValidationError):
            model(**body)


def test_owner_is_never_granted_by_invitation():
    with pytest.raises(ValidationError):
        MemberInvite(email="a@b.co", role="owner")


def test_webhook_urls_are_https():
    WebhookCreate(url="https://hooks.yoursite.com/ocheso", events=["tournament.started"])
    for url in ("http://hooks.yoursite.com", "https://x.com/a b"):
        with pytest.raises(ValidationError):
            WebhookCreate(url=url, events=["tournament.started"])
    with pytest.raises(ValidationError):
        WebhookCreate(url="https://x.com", events=["tournament.exploded"])


# --- the tournament's platform columns (C2) -------------------------------------

BASE = {"title": "Weekly Blitz", "game": "chess", "variant": "standard", "format": "arena", "clock_base_s": 180,
        "clock_increment_s": 2, "starts_at": "2026-10-30T18:00:00Z", "arena_minutes": 60}


@pytest.mark.parametrize("extra,ok", [
    ({"min_players": 2}, True), ({"min_players": 4096}, True), ({"min_players": 1}, False),
    ({"min_players": 4097}, False),
    ({"round_break_s": 0}, True), ({"round_break_s": 3600}, True), ({"round_break_s": 3601}, False),
    ({"postpone_min": 1}, True), ({"postpone_min": 0}, False), ({"postpone_min": 1441}, False),
    ({"max_postpones": 0}, True), ({"max_postpones": 50}, True), ({"max_postpones": 51}, False),
    ({"short_field": "cancel"}, True), ({"short_field": "skip"}, False),
    ({"language": "both"}, True), ({"language": "de"}, False),
    ({"identity_mode": "accounts"}, True),
    ({"identity_mode": "platform"}, False),           # identity_needs_org
    ({"identity_mode": "any", "org": "yoursite"}, True),
    ({"min_players": 8, "max_participants": 4}, False),
    ({"autopilot_note": "hi"}, False),                # system-written only
    ({"org_id": "00000000-0000-0000-0000-000000000000"}, False),  # by slug, as `org`
])
def test_tournament_platform_fields(extra, ok):
    if ok:
        TournamentCreate(**BASE, **extra)
    else:
        with pytest.raises(ValidationError):
            TournamentCreate(**BASE, **extra)
