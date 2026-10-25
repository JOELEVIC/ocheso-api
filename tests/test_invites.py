"""
Adding players by email (routers/invites.py): the CSV rules - separators,
English and French headers, encodings - and what add_invites is sent.
"""

import json

import pytest
from fastapi.testclient import TestClient

from fakedb import install
from main import app
from routers.invites import decode, invite_rows, parse_csv, sniff, InvitesIn

client = TestClient(app)


def jwt():
    import base64

    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return {"Authorization": f"Bearer {seg({'alg': 'HS256'})}.{seg({'sub': 'u1', 'role': 'authenticated'})}.sig"}


def emails(text):
    rows, _ = parse_csv(text)
    return [(r["email"], r["name"]) for r in rows]


@pytest.mark.parametrize("text,sep", [
    ("email,name\na@b.co,Ama", ","), ("email;name\na@b.co;Ama", ";"), ("email\tname\na@b.co\tAma", "\t"),
    ("a@b.co", ","), ('"Mensah, Ama";a@b.co\n"Kofi";k@b.co', ";"),
])
def test_separator_detection(text, sep):
    assert sniff(text) == sep


def test_english_header():
    assert emails("Name,Email\nAma Mensah,ama@example.com\n,kofi@example.com") == \
        [("ama@example.com", "Ama Mensah"), ("kofi@example.com", None)]


def test_french_header_with_first_and_last_names():
    text = "Prénom;Nom;Courriel\nAmina;Ngo;amina@example.cm\nÉbène;Mbarga;ebene@example.cm"
    assert emails(text) == [("amina@example.cm", "Amina Ngo"), ("ebene@example.cm", "Ébène Mbarga")]


@pytest.mark.parametrize("header", ["E-mail", "e-mail", "Mail", "Adresse e-mail", "COURRIEL", "Email Address"])
def test_email_header_aliases(header):
    assert emails(f"{header},Name\nx@y.co,X") == [("x@y.co", "X")]


def test_utf8_with_a_bom_and_cp1252():
    assert decode("﻿email,nom\na@b.co,Éloïse".encode("utf-8")) == "email,nom\na@b.co,Éloïse"
    # Excel on a French Windows machine: not UTF-8 at all.
    assert decode("email;prénom\na@b.co;Éloïse".encode("cp1252")) == "email;prénom\na@b.co;Éloïse"


def test_no_header_finds_the_address_on_each_line():
    text = "Ama Mensah <ama@example.com>\nkofi@example.com\nBea Ngo, bea@example.com\n@someone\n\n"
    rows, problems = parse_csv(text)
    assert [(r["email"], r["name"], r["row"]) for r in rows] == [
        ("ama@example.com", "Ama Mensah", 1), ("kofi@example.com", None, 2), ("bea@example.com", "Bea Ngo", 3)]
    assert problems == [{"row": 4, "reason": "no email address on this line"}]


def test_clean_lowercases_dedupes_and_flags():
    good, problems = invite_rows(InvitesIn(csv="email,name\nAma@Example.com,Ama\nama@example.com,Again\nnope,X\n"
                                                "b@c.co," + "n" * 80))
    assert [g["email"] for g in good] == ["ama@example.com", "b@c.co"]
    assert len(good[1]["name"]) == 60
    assert problems == [{"row": 3, "reason": "duplicate"}, {"row": 4, "reason": "not an email address"}]


def test_rows_and_csv_are_one_or_the_other():
    with pytest.raises(ValueError):
        InvitesIn(rows=[{"email": "a@b.co"}], csv="a@b.co")
    with pytest.raises(ValueError):
        InvitesIn()


# --- the route ---------------------------------------------------------------

TOURNAMENT = [{"id": "t1", "slug": "weekly"}]


def test_add_sends_clean_rows_with_the_note_and_maps_refusals_back(monkeypatch):
    def add_invites(params):
        return {"added": 1, "already": 0, "invalid": [{"row": 2, "reason": "suppressed"}], "places_left": 3}

    log = install(monkeypatch, {"get_tournament": TOURNAMENT, "add_invites": add_invites})
    body = {"csv": "email,name\nama@example.com,Ama\nbad\nkofi@example.com,Kofi", "send": False, "note": "See you"}
    r = client.post("/v1/tournaments/weekly/invites", json=body, headers=jwt())
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["added"] == 1 and out["places_left"] == 3
    assert out["invalid"] == [{"row": 3, "reason": "not an email address"},
                              {"row": 4, "email": "kofi@example.com", "reason": "suppressed"}]
    [params] = [p for _, _, fn, p in log if fn == "add_invites"]
    assert params["p_tournament"] == "t1" and params["p_send"] is False
    assert params["p_rows"] == [{"email": "ama@example.com", "name": "Ama", "note": "See you"},
                                {"email": "kofi@example.com", "name": "Kofi", "note": "See you"}]


def test_a_raw_cp1252_csv_upload(monkeypatch):
    log = install(monkeypatch, {"get_tournament": TOURNAMENT,
                                "add_invites": {"added": 1, "already": 0, "invalid": [], "places_left": None}})
    raw = "Courriel;Prénom\neloise@example.fr;Éloïse".encode("cp1252")
    r = client.post("/v1/tournaments/weekly/invites?send=false", content=raw,
                    headers={**jwt(), "Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    [params] = [p for _, _, fn, p in log if fn == "add_invites"]
    assert params["p_rows"][0]["name"] == "Éloïse" and params["p_send"] is False


def test_nothing_valid_means_no_database_write(monkeypatch):
    log = install(monkeypatch, {"get_tournament": TOURNAMENT})
    r = client.post("/v1/tournaments/weekly/invites", json={"rows": [{"email": "nope"}]}, headers=jwt())
    assert r.status_code == 200 and r.json()["added"] == 0
    assert not [fn for _, _, fn, _ in log if fn == "add_invites"]


def test_at_most_500_at_a_time(monkeypatch):
    install(monkeypatch, {"get_tournament": TOURNAMENT})
    rows = [{"email": f"p{i}@example.com"} for i in range(501)]
    assert client.post("/v1/tournaments/weekly/invites", json={"rows": rows}, headers=jwt()).status_code == 422


def test_adding_needs_sign_in_before_anything_else(monkeypatch):
    log = install(monkeypatch)
    assert client.post("/v1/tournaments/weekly/invites", json={}).status_code == 401
    assert log == []


@pytest.mark.parametrize("token", ["short", "0123456789ABCDEF0123456789ABCDEF", "../../etc"])
def test_invite_links_are_checked_before_the_database(monkeypatch, token):
    log = install(monkeypatch)
    assert client.get(f"/v1/invites/by-token/{token}").status_code == 404
    assert log == []


def test_preview_is_public_and_never_cached(monkeypatch):
    install(monkeypatch, {"get_invite_preview": {"title": "Weekly", "email": "am•••@gmail.com", "status": "pending"}})
    r = client.get("/v1/invites/by-token/0123456789abcdef0123456789abcdef")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
