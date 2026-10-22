"""
Shared setup for the end-to-end suites: the real API, in-process, talking to a
real PostgREST over a throwaway local database, with players whose tokens are
minted from a local secret. Local only - nothing here reaches a real project.

Run through db/test/e2e_play.sh, which sets up the database and PostgREST.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import subprocess
import sys
import time
import uuid

DB = os.environ["E2E_DB"]
JWT_SECRET = os.environ["E2E_JWT_SECRET"]
REST = os.environ["E2E_REST"]


def jwt(claims: dict) -> str:
    def seg(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")

    head = seg({"alg": "HS256", "typ": "JWT"})
    body = seg({**claims, "exp": int(time.time()) + 3600})
    sig = hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


ANON_KEY = jwt({"role": "anon"})
os.environ["SUPABASE_URL"] = REST
os.environ["SUPABASE_ANON_KEY"] = ANON_KEY
os.environ.pop("SUPABASE_KEY", None)
os.environ["REFEREE_SECRET"] = subprocess.run(
    ["psql", DB, "-tAc", "select secret from private.referee"], capture_output=True, text=True, check=True
).stdout.strip()

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
# The light API lives in core/ (its own Vercel function); dev.py serves both halves.
sys.path[:0] = [os.path.join(_ROOT, "core"), _ROOT]
import db as dbmod  # noqa: E402
from postgrest import SyncPostgrestClient  # noqa: E402


def _local_client(bearer: str) -> SyncPostgrestClient:
    # PostgREST serves at its root; Supabase puts it under /rest/v1.
    return SyncPostgrestClient(REST, headers={"apikey": ANON_KEY, "Authorization": f"Bearer {bearer}"})


dbmod._client = _local_client
from fastapi.testclient import TestClient  # noqa: E402

from dev import app  # noqa: E402  (the whole API, both functions)

api = TestClient(app)
results: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"{'ok  ' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n      -> {detail}"), flush=True)


def sql(q: str) -> str:
    return subprocess.run(["psql", DB, "-tAc", q], capture_output=True, text=True, check=True).stdout.strip()


class Player:
    def __init__(self, name: str):
        self.id = str(uuid.uuid4())
        self.name = name
        sql(f"insert into auth.users (id, email, raw_user_meta_data) values "
            f"('{self.id}', '{name}@e2e.test', '{{\"full_name\":\"{name}\"}}')")
        self.h = {"Authorization": f"Bearer {jwt({'sub': self.id, 'role': 'authenticated'})}"}

    def get(self, path: str):
        return api.get(path, headers=self.h)

    def post(self, path: str, body: dict | None = None):
        return api.post(path, headers=self.h, json=body if body is not None else {})

    def patch(self, path: str, body: dict):
        return api.patch(path, headers=self.h, json=body)

    def put(self, path: str, body: dict):
        return api.put(path, headers=self.h, json=body)

    def delete(self, path: str):
        return api.delete(path, headers=self.h)


class Anonymous:
    """A visitor with no account: requests carry no token at all."""

    id = None
    name = "visitor"

    def get(self, path: str):
        return api.get(path)


def expect(name: str, resp, status: int = 200):
    ok = resp.status_code == status
    check(name, ok, f"{resp.status_code} {resp.text[:300]}")
    return resp.json() if resp.content else None


def tournament(owner: Player, players: list[Player], **kw) -> str:
    body = {
        "title": kw.pop("title"), "game": "chess", "variant": "standard", "format": "swiss",
        "clock_base_s": 300, "clock_increment_s": 2, "starts_at": "2030-01-01T10:00:00Z", **kw,
    }
    t = expect(f"{body['title']}: created", owner.post("/v1/tournaments", body), 201)
    slug = t["slug"]
    expect(f"{body['title']}: entries open", owner.post(f"/v1/tournaments/{slug}/publish"))
    for p in players:
        r = p.post(f"/v1/tournaments/{slug}/join", {})
        if r.status_code != 200:
            check(f"{p.name} joins {slug}", False, r.text)
    expect(f"{body['title']}: started", owner.post(f"/v1/tournaments/{slug}/start"))
    return slug




def report() -> int:
    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return len(failed)
