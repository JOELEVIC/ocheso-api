"""
Players by email (docs/OCHESO_PLATFORMS.md A2, C5, D1).

An organiser adds addresses - pasted, or a CSV - and each person is entered
the first time they sign in with that address confirmed. Nothing here, and
nothing in add_invites, looks at whether an address has an account: the
answer for a stranger's address and a member's is the same, so adding
players can never be used to find out who is on Ocheso.

The parsing is the server's so every client gets the same rules: separators
detected (`,` `;` tab), headers in English or French (email/e-mail/courriel/
mail; name/nom/prénom/first/last), UTF-8 with or without a BOM, and Windows
cp1252 when the bytes are not UTF-8 - what Excel saves on a French machine.
"""

from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from typing import Annotated, Optional

from fastapi import APIRouter, HTTPException, Path, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from db import CallerDb, UserDb, one, rows
from routers.tournaments import find
from schemas.org import email_ok
from tokens import INVITE_TOKEN

router = APIRouter(tags=["Invites"])

MAX_ROWS = 500
MAX_CSV_BYTES = 512_000
UUID = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
INVITE_COLUMNS = "id,email,name,note,status,send,sent_at,send_error,resends,opened_at,claimed_at,claimed_by,created_at"


class InviteRow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=320)
    name: Optional[str] = Field(None, max_length=200)


class InvitesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rows: Optional[list[InviteRow]] = Field(None, max_length=MAX_ROWS * 2)
    csv: Optional[str] = Field(None, max_length=MAX_CSV_BYTES)
    send: bool = True
    note: Optional[str] = Field(None, max_length=500)

    @model_validator(mode="after")
    def _one_source(self) -> "InvitesIn":
        if (self.rows is None) == (self.csv is None):
            raise ValueError("Send rows or csv, not both.")
        return self


# -----------------------------------------------------------------------------
# Parsing
# -----------------------------------------------------------------------------
_EMAIL_HEADERS = {"email", "courriel", "mail", "emailaddress", "adresseemail", "adressemail",
                  "adressecourriel", "adresseelectronique"}
_FIRST_HEADERS = {"prenom", "first", "firstname", "givenname"}
_LAST_HEADERS = {"nom", "last", "lastname", "surname", "familyname", "nomdefamille"}
_NAME_HEADERS = {"name", "fullname", "nomcomplet", "displayname", "joueur", "player"}
_ANGLE = re.compile(r"^\s*(.*?)\s*<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$")


def decode(raw: bytes) -> str:
    """UTF-8 (a BOM dropped), else cp1252: a file Excel saved on Windows."""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def _key(cell: str) -> str:
    """'Prénom', 'E-mail ', 'Courriel' -> 'prenom', 'email', 'courriel'."""
    plain = unicodedata.normalize("NFKD", cell).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z]", "", plain)


def sniff(text: str) -> str:
    """The separator: whichever of , ; tab the first lines use most, outside
    quotes. A single column (one address a line) parses with any of them."""
    sample = [line for line in text.splitlines() if line.strip()][:5]
    best, score = ",", 0
    for sep in (",", ";", "\t"):
        counts = [len(next(csv.reader([line], delimiter=sep))) - 1 for line in sample]
        if counts and min(counts) > score:
            best, score = sep, min(counts)
    return best


def parse_csv(text: str) -> tuple[list[dict], list[dict]]:
    """(rows [{email, name, row}], problems [{row, reason}]). `row` is the
    line number a person would see in their spreadsheet."""
    text = text.lstrip("﻿")
    if not text.strip():
        return [], []
    sep = sniff(text)
    lines = list(csv.reader(io.StringIO(text), delimiter=sep))
    header = [_key(c) for c in lines[0]] if lines else []
    email_col = next((i for i, h in enumerate(header) if h in _EMAIL_HEADERS), None)
    out: list[dict] = []
    problems: list[dict] = []
    if email_col is not None:
        name_cols = [i for i, h in enumerate(header) if h in _NAME_HEADERS]
        first = [i for i, h in enumerate(header) if h in _FIRST_HEADERS]
        last = [i for i, h in enumerate(header) if h in _LAST_HEADERS]
        for n, cells in enumerate(lines[1:], start=2):
            if not any(c.strip() for c in cells):
                continue
            cell = lambda i: cells[i].strip() if i < len(cells) else ""  # noqa: E731
            name = " ".join(x for x in [cell(i) for i in name_cols] if x) or \
                " ".join(x for x in [cell(i) for i in first + last] if x)
            out.append({"email": cell(email_col), "name": name or None, "row": n})
        return out, problems
    # No header: each line holds an address somewhere, and maybe a name.
    for n, cells in enumerate(lines, start=1):
        cells = [c.strip() for c in cells if c.strip()]
        if not cells:
            continue
        email, name = None, []
        for c in cells:
            m = _ANGLE.match(c)
            if m:
                email = email or m.group(2)
                if m.group(1):
                    name.append(m.group(1).strip('"'))
            elif "@" in c and email is None and not c.startswith("@"):
                email = c
            else:
                name.append(c)
        if email is None:
            problems.append({"row": n, "reason": "no email address on this line"})
            continue
        out.append({"email": email, "name": " ".join(name) or None, "row": n})
    return out, problems


def clean(found: list[dict]) -> tuple[list[dict], list[dict]]:
    """Lower-cased, trimmed, checked the way tournament_invites checks, and
    each address once. Names longer than the column takes are shortened."""
    seen: set[str] = set()
    good: list[dict] = []
    problems: list[dict] = []
    for r in found:
        email = (r.get("email") or "").strip().strip("<>").lower()
        if not email_ok(email):
            problems.append({"row": r["row"], "reason": "not an email address"})
            continue
        if email in seen:
            problems.append({"row": r["row"], "reason": "duplicate"})
            continue
        seen.add(email)
        name = (r.get("name") or "").strip()[:60].strip() or None
        good.append({"email": email, "name": name, "row": r["row"]})
    return good, problems


def invite_rows(body: InvitesIn) -> tuple[list[dict], list[dict]]:
    if body.csv is not None:
        found, problems = parse_csv(body.csv)
    else:
        found = [{"email": r.email, "name": r.name, "row": n} for n, r in enumerate(body.rows or [], start=1)]
        problems = []
    good, bad = clean(found)
    return good, sorted(problems + bad, key=lambda p: p["row"])


async def _body(request: Request) -> InvitesIn:
    """JSON {rows | csv, send?, note?}, or the CSV file itself as text/csv
    with ?send=&note= - the only way the cp1252 fallback can help, because a
    browser that read a cp1252 file as UTF-8 has already lost the accents."""
    kind = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    raw = await request.body()
    if len(raw) > MAX_CSV_BYTES + 4096:
        raise HTTPException(status_code=413, detail="That file is too big: 500 players at a time.")
    try:
        if kind in ("text/csv", "text/plain", "application/csv", "text/tab-separated-values"):
            q = request.query_params
            return InvitesIn(csv=decode(raw), send=q.get("send", "true").lower() not in ("false", "0", "no"),
                             note=q.get("note") or None)
        return InvitesIn.model_validate(json.loads(raw or b"{}"))
    except ValidationError as e:
        raise RequestValidationError(e.errors()) from None
    except ValueError:
        raise HTTPException(status_code=400, detail="Send JSON, or the CSV itself as text/csv.") from None


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@router.post(
    "/v1/tournaments/{slug}/invites",
    summary="Add players by email (rows, pasted CSV, or a text/csv upload)",
    openapi_extra={"requestBody": {"content": {
        "application/json": {"schema": InvitesIn.model_json_schema()},
        "text/csv": {"schema": {"type": "string"}},
    }}},
)
async def add(slug: str, request: Request, db: UserDb):
    body = await _body(request)
    good, problems = invite_rows(body)
    if len(good) > MAX_ROWS:
        raise HTTPException(status_code=422, detail=f"Add at most {MAX_ROWS} players at a time.")
    return await run_in_threadpool(_add, slug, db, good, problems, body)


def _add(slug: str, db, good: list[dict], problems: list[dict], body: InvitesIn) -> dict:
    t = find(db, slug)
    if not good:
        return {"added": 0, "already": 0, "invalid": problems, "places_left": None}
    # The note travels with each row: tournament_invites keeps it per address,
    # and the email for that address is rendered from the row.
    payload = [{"email": r["email"], "name": r["name"], "note": body.note} for r in good]
    result = one(db.rpc("add_invites", {"p_tournament": t["id"], "p_rows": payload, "p_send": body.send}).execute())
    # The database numbers its own refusals by position in what it was sent;
    # turn them back into the line numbers the organiser pasted.
    for bad in result.get("invalid") or []:
        i = bad.get("row")
        if isinstance(i, int) and 1 <= i <= len(good):
            problems.append({"row": good[i - 1]["row"], "email": good[i - 1]["email"], "reason": bad.get("reason")})
        else:
            problems.append(bad)
    return {**result, "invalid": sorted(problems, key=lambda p: p.get("row") or 0)}


@router.get("/v1/tournaments/{slug}/invites", summary="Everyone invited by email, and where each stands")
def list_invites(slug: str, db: UserDb):
    # Organisers only - tournament_invites' read policy - and never the token.
    t = find(db, slug)
    return rows(
        db.table("tournament_invites").select(INVITE_COLUMNS).eq("tournament_id", t["id"]).order("created_at").execute()
    )


@router.delete("/v1/invites/{invite_id}", status_code=204, summary="Revoke an invite")
def revoke(invite_id: Annotated[str, Path(pattern=UUID)], db: UserDb):
    db.rpc("revoke_invite", {"p_invite": invite_id}).execute()
    return Response(status_code=204)


@router.post("/v1/invites/{invite_id}/resend", summary="Send the invitation again (3 times at most, an hour apart)")
def resend(invite_id: Annotated[str, Path(pattern=UUID)], db: UserDb):
    return one(db.rpc("resend_invite", {"p_invite": invite_id}).execute())


@router.get("/v1/me/invites", summary="Invitations to your address: waiting, and just claimed")
def my_invites(db: UserDb):
    return rows(db.rpc("my_invites", {}).execute())


def _token(token: str) -> str:
    if not INVITE_TOKEN.fullmatch(token):
        raise HTTPException(status_code=404, detail="This invitation link isn't valid.")
    return token


@router.get("/v1/invites/by-token/{token}", summary="What an invitation link is for (the address masked)")
def preview(token: str, db: CallerDb, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return one(db.rpc("get_invite_preview", {"p_token": _token(token)}).execute(),
               missing="This invitation link isn't valid.")


@router.post("/v1/invites/by-token/{token}/accept", summary="Accept: you're in")
def accept(token: str, db: UserDb):
    return one(db.rpc("accept_invite", {"p_token": _token(token)}).execute())


@router.post("/v1/invites/by-token/{token}/decline", summary="Decline the invitation")
def decline(token: str, db: UserDb):
    return one(db.rpc("decline_invite", {"p_token": _token(token)}).execute())
