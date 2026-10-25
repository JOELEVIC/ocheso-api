"""
Invitation mail (core/mail.py): the copy, the link, the escaping, and what
goes to Resend - with Resend replaced by httpx's MockTransport, so nothing is
ever sent from a test.
"""

import json

import httpx
import pytest

import mail
from config import settings

TOKEN = "0123456789abcdef0123456789abcdef"
DATA = {
    "token": TOKEN, "slug": "weekly-blitz", "title": "Weekly Blitz", "starts_at": "2026-10-30T18:00:00Z",
    "timezone": "Africa/Douala", "game": "chess", "variant": "standard", "format": "arena",
    "clock_base_s": 180, "clock_increment_s": 2,
    "org": {"slug": "yoursite", "name": "Yoursite", "support_email": "team@yoursite.com"},
    "note": "Bring a friend.",
}


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(settings, "RESEND_API_KEY", "re_test_key")
    monkeypatch.setattr(settings, "MAIL_FROM", "Ocheso <invites@ocheso.com>")
    monkeypatch.setattr(settings, "SITE_URL", "https://www.ocheso.com")


@pytest.mark.parametrize("email,masked", [
    ("amina@gmail.com", "am•••@gmail.com"), ("ab@x.co", "a•••@x.co"), ("a@x.co", "a•••@x.co"), ("nope", "•••"),
])
def test_mask(email, masked):
    assert mail.mask(email) == masked


def test_english_invitation():
    r = mail.render_invite("amina@gmail.com", "en", DATA)
    # 18:00 UTC is 19:00 in Douala, on a Friday.
    assert r["subject"] == "You're invited: Weekly Blitz, Fri 30 Oct, 19:00"
    assert "I&#x27;m in, open the tournament" in r["html"] or "I'm in, open the tournament" in r["html"]
    assert "am•••@gmail.com" in r["text"] and "6-digit code, no password" in r["text"]
    assert "Chess · Arena · 3+2" in r["text"]
    assert "Bring a friend." in r["text"]
    assert f"https://www.ocheso.com/o/yoursite/weekly-blitz?invite={TOKEN}" in r["text"]
    assert r["reply_to"] == "team@yoursite.com" and r["org"] == "Yoursite"


def test_french_invitation():
    r = mail.render_invite("amina@gmail.com", "fr", DATA)
    assert r["subject"] == "Invitation : Weekly Blitz, ven. 30 oct., 19:00"
    assert "J'y vais, ouvrir le tournoi" in r["text"]
    assert "code à 6 chiffres, sans mot de passe" in r["text"]
    assert "Échecs · Arène · 3+2" in r["text"]
    assert 'lang="fr"' in r["html"]


def test_both_languages_in_one_email():
    r = mail.render_invite("amina@gmail.com", "both", DATA)
    assert r["subject"].startswith("You're invited:") and "Invitation :" in r["subject"]
    assert "I'm in, open the tournament" in r["text"] and "J'y vais, ouvrir le tournoi" in r["text"]


def test_the_invitation_never_hints_at_an_account():
    for locale in ("en", "fr", "both"):
        text = mail.render_invite("amina@gmail.com", locale, DATA)["text"].lower()
        assert "account" not in text and "welcome back" not in text and "compte" not in text


def test_organiser_text_is_escaped():
    data = {**DATA, "title": 'Blitz <img src=x onerror=alert(1)>', "note": "<script>alert(1)</script>\nline two",
            "org": {**DATA["org"], "name": 'Evil "Org" <b>'}}
    r = mail.render_invite("a@b.co", "en", data)
    assert "<script>" not in r["html"] and "<img" not in r["html"] and "<b>" not in r["html"]
    assert "&lt;script&gt;" in r["html"] and "<br>line two" in r["html"]


@pytest.mark.parametrize("extra,url", [
    ({}, f"https://www.ocheso.com/o/yoursite/weekly-blitz?invite={TOKEN}"),
    ({"partner_url": "https://yoursite.com/club?tab=events"},
     f"https://yoursite.com/club?tab=events&ocheso_invite={TOKEN}&ocheso_t=weekly-blitz"),
    ({"partner_url": "javascript:alert(1)"}, f"https://www.ocheso.com/o/yoursite/weekly-blitz?invite={TOKEN}"),
    ({"org": None}, f"https://www.ocheso.com/invite/weekly-blitz?e={TOKEN}"),
])
def test_where_im_in_goes(extra, url):
    assert mail.invite_url({**DATA, **extra}) == url


@pytest.mark.parametrize("install,page", [
    ({"origin": "https://yoursite.com", "path": "/club/blitz"}, "https://yoursite.com/club/blitz"),
    ({"origin": "https://yoursite.com:8443", "path": "/"}, "https://yoursite.com:8443/"),
    # Anything the database should never have handed over is still refused:
    ({"origin": "https://yoursite.com", "path": None}, None),            # the home page has no embed
    ({"origin": "http://yoursite.com", "path": "/club"}, None),          # not https
    ({"origin": "https://yoursite.com", "path": "//evil.example/x"}, None),
    ({"origin": "https://yoursite.com", "path": "/go?to=https://evil.example"}, None),
    ({"origin": "https://yoursite.com", "path": "/a/../b"}, None),
    ({"origin": "https://yoursite.com", "path": "/x%2F%2Fevil.example"}, None),
    ({"origin": "https://user@evil.example", "path": "/x"}, None),
    (None, None),
])
def test_a_partner_page_is_an_https_origin_and_a_plain_path(install, page):
    assert mail.partner_page(install) == page


def test_an_invite_without_a_usable_install_links_the_hosted_page():
    inv = {**BATCH["invites"][0], "install": {"origin": "https://yoursite.com", "path": "//evil.example"}}
    msg = mail.from_batch({"invites": [inv]})[0]
    assert msg["data"]["partner_url"] is None
    assert f"https://www.ocheso.com/o/yoursite/weekly-blitz?invite={TOKEN}" in mail.render(msg)["text"]


def test_sender_is_the_org_via_ocheso_and_cannot_break_the_header():
    assert mail.sender("Yoursite") == "Yoursite via Ocheso <invites@ocheso.com>"
    assert mail.sender(None) == "Ocheso <invites@ocheso.com>"
    nasty = mail.sender('Evil"\r\nBcc: x@y.z <a>')
    assert "\n" not in nasty and "\r" not in nasty and nasty.endswith("<invites@ocheso.com>")


def _transport(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_a_batch_goes_to_resend_and_each_message_gets_its_result():
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"id": "re_1"}, {"id": "re_3"}],
                                         "errors": [{"index": 1, "message": "bounced recently"}]})

    batch = [
        {"id": 1, "to": "amina@gmail.com", "template": "invite", "locale": "en", "data": DATA},
        {"id": 2, "to": "kofi@example.com", "template": "invite", "locale": "fr", "data": DATA},
        {"id": 3, "to": "bea@example.com", "template": "invite", "locale": "both", "data": DATA},
        {"id": 4, "to": "not an address", "template": "invite", "locale": "en", "data": DATA},
        {"id": 5, "to": "x@example.com", "template": "mystery", "locale": "en", "data": {}},
    ]
    out = mail.send_outbox(batch, client=_transport(handler))
    assert seen["url"] == "https://api.resend.com/emails/batch"
    assert seen["headers"]["authorization"] == "Bearer re_test_key"
    assert seen["headers"]["idempotency-key"].startswith("ocheso-mail-")
    assert seen["headers"]["x-batch-validation"] == "permissive"
    assert [e["to"] for e in seen["body"]] == [["amina@gmail.com"], ["kofi@example.com"], ["bea@example.com"]]
    assert seen["body"][0]["from"] == "Yoursite via Ocheso <invites@ocheso.com>"
    assert seen["body"][0]["reply_to"] == "team@yoursite.com"
    by_id = {r["id"]: r for r in out}
    assert by_id[1] == {"id": 1, "ok": True, "provider_id": "re_1"}
    assert by_id[2]["ok"] is False and by_id[2]["permanent"] and "bounced" in by_id[2]["error"]
    assert by_id[3] == {"id": 3, "ok": True, "provider_id": "re_3"}
    assert by_id[4]["ok"] is False and by_id[4]["error"] == "invalid address"
    assert by_id[5]["ok"] is False and by_id[5]["permanent"] and "unknown template" in by_id[5]["error"]
    assert [r["id"] for r in out] == [1, 2, 3, 4, 5]


def test_the_same_send_of_the_same_rows_has_the_same_idempotency_key():
    keys = []

    def handler(request):
        keys.append(request.headers["idempotency-key"])
        return httpx.Response(200, json={"data": [{"id": "a"}, {"id": "b"}]})

    batch = [{"id": i, "to": f"p{i}@example.com", "template": "invite", "locale": "en", "data": DATA} for i in (7, 8)]
    mail.send_outbox(batch, client=_transport(handler))
    mail.send_outbox(list(reversed(batch)), client=_transport(handler))
    assert keys[0] == keys[1]


def test_a_resend_is_a_new_send_with_a_new_key():
    # An invite's id never changes; its resend count does (resend_invite, or
    # the address added again). With the id alone Resend would answer a
    # resend with the first send's cached success and deliver nothing.
    keys = []

    def handler(request):
        keys.append(request.headers["idempotency-key"])
        return httpx.Response(200, json={"data": [{"id": "a"}]})

    first = mail.from_batch({"invites": [{**BATCH["invites"][0], "resends": 0}]})
    again = mail.from_batch({"invites": [{**BATCH["invites"][0], "resends": 1}]})
    mail.send_outbox(first, client=_transport(handler))
    mail.send_outbox(first, client=_transport(handler))  # a tick that died before reporting
    mail.send_outbox(again, client=_transport(handler))
    assert keys[0] == keys[1] and keys[2] != keys[0]
    assert first[0]["attempt"] == 0 and again[0]["attempt"] == 1


@pytest.mark.parametrize("name,permanent", [("invalid_idempotent_request", True),
                                            ("concurrent_idempotent_requests", False), (None, False)])
def test_a_409_is_permanent_only_when_the_key_can_never_succeed(name, permanent):
    body = {"statusCode": 409, "message": "x"} | ({"name": name} if name else {})
    out = mail.send_outbox([{"id": 1, "to": "a@b.co", "template": "invite", "locale": "en", "data": DATA}],
                           client=_transport(lambda r: httpx.Response(409, json=body)))
    assert out[0]["ok"] is False and out[0]["permanent"] is permanent
    if permanent:
        assert "send it again" in out[0]["error"]


@pytest.mark.parametrize("status,permanent", [(500, False), (429, False), (401, False), (403, False), (422, True),
                                               (400, True)])
def test_a_refused_batch_fails_every_message(status, permanent):
    out = mail.send_outbox([{"id": 1, "to": "a@b.co", "template": "invite", "locale": "en", "data": DATA}],
                           client=_transport(lambda r: httpx.Response(status, json={"message": "no"})))
    assert out == [{"id": 1, "ok": False, "error": f"resend {status}", "permanent": permanent}]


def test_a_network_failure_is_retryable():
    def boom(request):
        raise httpx.ConnectError("down")

    out = mail.send_outbox([{"id": 1, "to": "a@b.co", "template": "invite", "locale": "en", "data": DATA}],
                           client=_transport(boom))
    assert out[0]["ok"] is False and "permanent" not in out[0]


@pytest.mark.parametrize("template", ["org_invite", "postponed", "stalled", "webhook_disabled"])
def test_notices_render(template):
    r = mail.render({"id": 1, "to": "owner@yoursite.com", "template": template, "locale": "en",
                     "data": {"title": "Weekly", "slug": "weekly", "org": {"slug": "yoursite", "name": "Yoursite"},
                              "starts_at": "2026-10-30T18:00:00Z", "timezone": "Africa/Douala", "reason": "board 4",
                              "token": TOKEN}})
    assert r["subject"] and r["text"] and "<html" in r["html"]


def test_a_staff_invitation_links_the_page_that_accepts_it():
    # Joining a team takes a yes (accept_invite): the invitation page, with
    # the token - never Studio, which signing in alone no longer joins.
    r = mail.render({"id": 1, "to": "kofi@example.com", "template": "org_invite", "locale": "en",
                     "data": {"token": TOKEN, "role": "staff", "org": {"slug": "yoursite", "name": "Yoursite"}}})
    assert f"https://www.ocheso.com/invite/yoursite?e={TOKEN}" in r["text"]
    assert "/studio/" not in r["text"] and "accept" in r["text"]
    with pytest.raises(mail.Unrenderable):
        mail.render({"id": 1, "to": "kofi@example.com", "template": "org_invite", "locale": "en",
                     "data": {"role": "staff", "org": {"slug": "yoursite", "name": "Yoursite"}}})


# --- the database's batch -----------------------------------------------------------

BATCH = {
    "invites": [{
        "id": "6f1c0000-0000-0000-0000-000000000001", "to": "amina@gmail.com", "name": "Amina", "note": "Bring a friend.",
        "token": TOKEN, "language": "fr", "resend": False,
        "tournament": {"id": "t1", "slug": "weekly-blitz", "title": "Weekly Blitz", "starts_at": "2026-10-30T18:00:00Z",
                       "game": "chess", "format": "arena", "clock": {"base_s": 180, "inc_s": 2}},
        "org": {"slug": "yoursite", "name": "Yoursite", "website": "https://yoursite.com",
                "support_email": "team@yoursite.com", "timezone": "Africa/Douala", "logo_url": None, "plan": "club"},
        "install": {"origin": "https://yoursite.com", "path": "/club/blitz"},
        "invited_by": "Joel",
    }],
    "outbox": [
        {"id": 41, "kind": "org-invite", "to": "kofi@example.com",
         "data": {"token": TOKEN, "role": "staff", "org": {"slug": "yoursite", "name": "Yoursite"}, "invited_by": "Joel"},
         "org": {"slug": "yoursite", "name": "Yoursite", "support_email": "team@yoursite.com"}},
        {"id": 42, "kind": "postponed", "to": "owner@yoursite.com",
         "data": {"slug": "weekly-blitz", "title": "Weekly Blitz", "starts_at": "2026-10-30T18:15:00Z",
                  "note": None, "approved": 3, "min_players": 4},
         "org": {"slug": "yoursite", "name": "Yoursite", "support_email": None}},
        {"id": 43, "kind": "webhook-disabled", "to": "owner@yoursite.com",
         "data": {"webhook": "w1", "url": "https://hooks.yoursite.com/x", "reason": "3 days of failures"},
         "org": {"slug": "yoursite", "name": "Yoursite", "support_email": None}},
    ],
}


def test_a_batch_becomes_messages():
    msgs = mail.from_batch(BATCH)
    assert [m["id"] for m in msgs] == ["invite:6f1c0000-0000-0000-0000-000000000001", "outbox:41", "outbox:42",
                                       "outbox:43"]
    assert [m["template"] for m in msgs] == ["invite", "org_invite", "postponed", "webhook_disabled"]
    invite = mail.render(msgs[0])
    # The partner page where the embed was seen, in the event's language and the organiser's timezone.
    assert f"https://yoursite.com/club/blitz?ocheso_invite={TOKEN}&ocheso_t=weekly-blitz" in invite["text"]
    assert invite["subject"] == "Invitation : Weekly Blitz, ven. 30 oct., 19:00"
    assert invite["reply_to"] == "team@yoursite.com"
    staff = mail.render(msgs[1])
    assert "Joel invited you to Yoursite" in staff["text"] and f"/invite/yoursite?e={TOKEN}" in staff["text"]
    late = mail.render(msgs[2])
    # The outbox row's org carries no timezone, so the owner's notice says UTC.
    assert "3 of 4 players" in late["text"] and "18:15 UTC" in late["text"]
    assert "hooks.yoursite.com" in mail.render(msgs[3])["text"]


def test_results_go_back_split_by_table_without_the_transient_ones():
    results = [{"id": "invite:abc", "ok": True, "provider_id": "re_1"},
               {"id": "outbox:41", "ok": False, "error": "render: x", "permanent": True},
               {"id": "outbox:42", "ok": False, "error": "resend 503"}]
    assert mail.to_done(results) == {"invites": [{"id": "abc", "ok": True}],
                                     "outbox": [{"id": 41, "ok": False, "error": "render: x"}]}


def test_a_personal_event_says_its_time_is_utc():
    data = {**DATA, "org": None, "timezone": None}
    assert mail.render_invite("a@b.co", "en", data)["subject"] == "You're invited: Weekly Blitz, Fri 30 Oct, 18:00 UTC"
