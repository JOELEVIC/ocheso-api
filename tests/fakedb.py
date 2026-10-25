"""
A stand-in for the PostgREST client, for tests that must prove what the API
SENDS - which function, which payload, as which bearer - without a database.

    clients = install(monkeypatch, {"org_call": {...}, "me": [...]})

Every client the API makes (db._client) is recorded with its bearer, and every
rpc/table call with its arguments. An answer may be data, a callable taking the
params, or an exception to raise.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any


class FakeQuery:
    def __init__(self, client: "FakeClient", kind: str, name: str, params: Any = None):
        self.client, self.kind, self.name, self.params = client, kind, name, params
        self.ops: list[tuple] = []

    def __getattr__(self, op):
        def chain(*args, **kwargs):
            self.ops.append((op, args, kwargs))
            return self
        return chain

    @property
    def not_(self):
        return self

    def execute(self):
        answer = self.client.answers.get(self.name)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            answer = answer(self.params if self.kind == "rpc" else self.ops)
        return SimpleNamespace(data=answer, count=len(answer) if isinstance(answer, list) else 0)


class FakeClient:
    def __init__(self, bearer: str, answers: dict, log: list):
        self.bearer, self.answers, self.log = bearer, answers, log

    def rpc(self, fn: str, params: dict) -> FakeQuery:
        self.log.append(("rpc", self.bearer, fn, params))
        return FakeQuery(self, "rpc", fn, params)

    def table(self, name: str) -> FakeQuery:
        self.log.append(("table", self.bearer, name, None))
        return FakeQuery(self, "table", name)


def install(monkeypatch, answers: dict | None = None, secret: str = "test-referee-secret") -> list:
    """Patch db._client; returns the call log [(kind, bearer, name, params)]."""
    import db
    from config import settings

    log: list = []
    monkeypatch.setattr(db, "_client", lambda bearer: FakeClient(bearer, answers if answers is not None else {}, log))
    monkeypatch.setattr(settings, "REFEREE_SECRET", secret)
    return log
