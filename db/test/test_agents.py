#!/usr/bin/env python3
"""
Tries to misuse db/agents.sql, and asserts that it cannot.

As test_play.py: real Postgres roles with a JWT subject, requests signed the
way the API signs them, with the key read as the superuser.

    python3 db/test/test_agents.py [postgres-url]

Needs supabase_shim.sql, schema.sql, play.sql and agents.sql applied.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
import time
import uuid

DB = sys.argv[1] if len(sys.argv) > 1 else "postgresql://postgres@127.0.0.1:55434/ocheso_test"

OWNER, OTHER = (str(uuid.uuid4()) for _ in range(2))
ANON = "anon"
results: list[tuple[bool, str, str]] = []


def sql(statement: str, who: str | None = None) -> tuple[bool, str]:
    prefix = ""
    if who == ANON:
        prefix = "set role anon; set request.jwt.claim.sub = '';"
    elif who is not None:
        prefix = f"set role authenticated; set request.jwt.claim.sub = '{who}';"
    p = subprocess.run(["psql", DB, "-v", "ON_ERROR_STOP=1", "-tAq", "-c", prefix + statement],
                       capture_output=True, text=True)
    if p.returncode == 0:
        return True, p.stdout.strip()
    return False, (p.stderr.strip().splitlines() or ["error"])[0]


def value(statement: str, who: str | None = None) -> str:
    ok, out = sql(statement, who)
    if not ok:
        report()
        raise SystemExit(f"\nsetup failed: {statement}\n{out}")
    return out


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append((passed, name, detail))


def allowed(name: str, statement: str, who: str, expect: str | None = None) -> str:
    ok, out = sql(statement, who)
    check(name, ok and (expect is None or out == expect), out)
    return out


def denied(name: str, statement: str, who: str, because: str | None = None) -> None:
    ok, out = sql(statement, who)
    check(name, not ok and (because is None or because in out), f"was allowed: {out!r}" if ok else out)


def report() -> int:
    failed = [r for r in results if not r[0]]
    for passed, name, detail in results:
        print(f"{'ok  ' if passed else 'FAIL'}  {name}" + ("" if passed else f"\n      -> {detail}"))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return len(failed)


SECRET = value("select secret from private.referee")


def q(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def signed(kind: str, body: dict, by: str | None = None, ttl: int = 60, key: str | None = None) -> str:
    payload = json.dumps({**body, "kind": kind, **({"by": by} if by else {}), "exp": int(time.time()) + ttl},
                         separators=(",", ":"), sort_keys=True)
    sig = hmac.new((key or SECRET).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{q(payload)}, '{sig}'"


def sha(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


PERSONA = {"game": "chess", "schemaVersion": 2, "archetype": "typical", "rating": 1200}

value("insert into auth.users (id, email) values "
      + ",".join(f"('{u}', '{n}@ocheso.test')" for u, n in [(OWNER, "agent-owner"), (OTHER, "agent-other")]))

# -----------------------------------------------------------------------------
# Building agents
# -----------------------------------------------------------------------------
denied("nobody inserts agents directly, persona and all",
       f"insert into agents (name, persona) values ('Sneaky', '{json.dumps(PERSONA)}')", OWNER)
denied("an unsigned persona is refused",
       f"select id from save_agent({q(json.dumps({'kind': 'agent-save', 'by': OWNER, 'name': 'X', 'persona': PERSONA, 'exp': 9999999999}))}, 'x')",
       OWNER, "did not sign")
denied("a persona signed for someone else is refused",
       f"select id from save_agent({signed('agent-save', {'name': 'X', 'persona': PERSONA}, by=OTHER)})", OWNER, "someone else")
denied("visitors cannot save agents",
       f"select id from save_agent({signed('agent-save', {'name': 'X', 'persona': PERSONA}, by=OWNER)})", ANON)
AGENT = allowed("the owner saves an agent the API signed",
                f"select id from save_agent({signed('agent-save', {'name': 'Ama', 'archetype': 'typical', 'persona': PERSONA}, by=OWNER)})",
                OWNER)
check("it starts as a draft, rated from its persona",
      value(f"select status || ' ' || rating from agents where id = '{AGENT}'") == "draft 1200")
denied("names are 2-40 characters",
       f"select id from save_agent({signed('agent-save', {'name': 'X', 'persona': PERSONA}, by=OWNER)})", OWNER, "check")
OTHERS = value(f"select id from save_agent({signed('agent-save', {'name': 'Kofi', 'persona': PERSONA}, by=OTHER)})", OTHER)

check("an owner sees only their own agents",
      value("select string_agg(name, ',') from agents", OWNER) == "Ama")
denied("visitors cannot read agents", "select count(*) from agents", ANON)
denied("a persona cannot be edited directly",
       f"update agents set persona = '{{}}' where id = '{AGENT}'", OWNER)
denied("an owner cannot be changed",
       f"update agents set owner_id = '{OTHER}' where id = '{AGENT}'", OWNER)
allowed("an owner renames their agent", f"update agents set name = 'Ama B' where id = '{AGENT}' returning name", OWNER, "Ama B")
allowed("someone else's agent cannot be renamed (no row matches)",
        f"update agents set name = 'Mine now' where id = '{OTHERS}' returning name", OWNER, "")
denied("someone else's persona cannot be overwritten",
       f"select id from save_agent({signed('agent-save', {'id': OTHERS, 'name': 'Mine', 'persona': PERSONA}, by=OWNER)})",
       OWNER, "no such agent")
denied("you can only copy your own agents",
       f"select id from save_agent({signed('agent-save', {'name': 'Copy', 'parent': OTHERS, 'persona': PERSONA}, by=OWNER)})",
       OWNER, "no such agent")
COPY = allowed("an owner copies their own agent",
               f"select id from save_agent({signed('agent-save', {'name': 'Ama copy', 'parent': AGENT, 'persona': {**PERSONA, 'rating': 1500}}, by=OWNER)})",
               OWNER)
check("the copy remembers where it came from",
      value(f"select parent_id = '{AGENT}' and rating = 1500 from agents where id = '{COPY}'") == "t")
allowed("a signed update changes the persona",
        f"select rating from save_agent({signed('agent-save', {'id': COPY, 'persona': {**PERSONA, 'rating': 1600}}, by=OWNER)})",
        OWNER, "1600")

# -----------------------------------------------------------------------------
# Keys
# -----------------------------------------------------------------------------
denied("visitors cannot make keys", "select create_agent_key('k')", ANON)
denied("keys cannot be inserted directly",
       f"insert into agent_keys (owner_id, name, prefix, hash) values ('{OWNER}', 'k', 'och_', '{'0' * 64}')", OWNER)
denied("a key cannot cover someone else's agent",
       f"select create_agent_key('k', array['{OTHERS}']::uuid[])", OWNER, "your own agents")
made = json.loads(allowed("an owner makes a key for one agent",
                          f"select create_agent_key('Test platform', array['{AGENT}']::uuid[])", OWNER))
RAW, KEY_ID = made["key"], made["id"]
check("the key is shown once, with a short prefix to recognise it",
      RAW.startswith("och_") and len(RAW) == 52 and made["prefix"] == RAW[:12])
check("only its hash is stored", value(f"select hash from agent_keys where id = '{KEY_ID}'") == sha(RAW))
denied("not even the owner can read the hash back", f"select hash from agent_keys where id = '{KEY_ID}'", OWNER)
check("the owner lists their keys",
      value("select string_agg(name || ' ' || prefix, ',') from agent_keys", OWNER) == f"Test platform {RAW[:12]}")
check("others don't see them", value("select count(*) from agent_keys", OTHER) == "0")
ALL_RAW = json.loads(value("select create_agent_key('All agents')", OWNER))["key"]
OTHER_RAW = json.loads(value("select create_agent_key('Theirs')", OTHER))["key"]

# -----------------------------------------------------------------------------
# A platform, through the API
# -----------------------------------------------------------------------------
denied("a key request the API did not sign is refused",
       f"select agent_machine_key({q(json.dumps({'kind': 'agent-key', 'key': sha(RAW), 'exp': 9999999999}))}, 'x')",
       ANON, "did not sign")
denied("an expired request is refused",
       f"select agent_machine_key({signed('agent-key', {'key': sha(RAW)}, ttl=-5)})", ANON, "expired")
denied("a request of another kind is refused",
       f"select agent_machine_key({signed('agent-use', {'key': sha(RAW)})})", ANON, "something else")
denied("an unknown key is refused",
       f"select agent_machine_key({signed('agent-key', {'key': sha('och_nope')})})", ANON, "not valid")
listed = json.loads(allowed("a valid key lists what it may drive",
                            f"select agent_machine_key({signed('agent-key', {'key': sha(RAW)})})", ANON))
check("...just the agent it was made for", [a["id"] for a in listed["agents"]] == [AGENT])
check("using a key stamps it", value(f"select last_used_at is not null from agent_keys where id = '{KEY_ID}'") == "t")

denied("a draft agent does not play",
       f"select agent_machine_use({signed('agent-use', {'key': sha(RAW), 'agent': AGENT})})", ANON, "is draft")
allowed("the owner activates it", f"update agents set status = 'active' where id = '{AGENT}' returning status", OWNER, "active")
used = json.loads(allowed("an active agent plays a one-off move",
                          f"select agent_machine_use({signed('agent-use', {'key': sha(RAW), 'agent': AGENT})})", ANON))
check("...and the API gets its persona", used["persona"]["rating"] == 1200)
value(f"update agents set status = 'active' where id = '{COPY}'", OWNER)
denied("a key cannot use an agent outside its list",
       f"select agent_machine_use({signed('agent-use', {'key': sha(RAW), 'agent': COPY})})", ANON, "cannot use")
denied("a key cannot use another owner's agent",
       f"select agent_machine_use({signed('agent-use', {'key': sha(ALL_RAW), 'agent': OTHERS})})", ANON, "cannot use")
allowed("an all-agents key uses any of its owner's",
        f"select agent_machine_use({signed('agent-use', {'key': sha(ALL_RAW), 'agent': COPY})}) ->> 'name'", ANON, "Ama copy")

opened = json.loads(allowed(
    "a platform opens a realtime session",
    f"select agent_machine_open({signed('agent-open', {'key': sha(RAW), 'agent': AGENT, 'color': 'white', 'cadence': '5+3', 'opponentRating': 1300, 'realtime': True, 'externalRef': 'game-42'})})",
    ANON))
S = opened["session"]
check("the session carries a channel and a secret, once",
      len(S["channel"]) == 32 and len(S["secret"]) == 64 and S["plies"] == 0 and opened["agent"]["id"] == AGENT)
denied("the owner can see the session but not its secret",
       f"select secret from agent_sessions where id = '{S['id']}'", OWNER)
check("the owner sees the session", value(f"select external_ref from agent_sessions where id = '{S['id']}'", OWNER) == "game-42")
check("nobody else does", value("select count(*) from agent_sessions", OTHER) == "0")
denied("another owner's key cannot read the session",
       f"select agent_machine_session({signed('agent-session', {'key': sha(OTHER_RAW), 'session': S['id']})})", ANON, "no such session")

state = {"mood": {"form": 12}}
deliver = {"event": "move", "payload": {"move": "e2e4", "sig": "x"}, "at": int(time.time() * 1000) - 1000}
allowed("the API records the agent's first move, already due",
        f"select agent_machine_record({signed('agent-record', {'key': sha(RAW), 'session': S['id'], 'plies': 0, 'state': state, 'deliver': deliver})}) ->> 'plies'",
        ANON, "1")
denied("a second move for the same turn is refused",
       f"select agent_machine_record({signed('agent-record', {'key': sha(RAW), 'session': S['id'], 'plies': 0, 'state': state})})",
       ANON, "recorded first")
read = json.loads(allowed("the session reads back with its state",
                          f"select agent_machine_session({signed('agent-session', {'key': sha(RAW), 'session': S['id']})})", ANON))
check("...one ply on, mood kept", read["session"]["plies"] == 1 and read["session"]["state"] == state)

check("a move already due is broadcast at once, publicly, on the session's channel",
      value("select count(*) from private.agent_outbox") == "0"
      and value("select topic || ' ' || event || ' ' || (payload ->> 'move') || ' ' || private from realtime.sent order by id desc limit 1")
      == f"agent:{S['channel']} move e2e4 false")
later = {**deliver, "at": int(time.time() * 1000) + 60_000}
value(f"select agent_machine_record({signed('agent-record', {'key': sha(RAW), 'session': S['id'], 'plies': 1, 'state': state, 'deliver': later})})")
check("a later move waits in the outbox", value("select count(*) from private.agent_outbox") == "1")
denied("nobody else can read the outbox", "select count(*) from private.agent_outbox", OWNER)
denied("nobody else can deliver it", "select private.deliver_agent_outbox()", ANON)
check("a move not yet due stays put", value("select private.deliver_agent_outbox()") == "0")
value("update private.agent_outbox set deliver_at = now()")
check("once due, the tick broadcasts it", value("select private.deliver_agent_outbox()") == "1"
      and value("select count(*) from private.agent_outbox") == "0")

allowed("the owner pauses the agent", f"update agents set status = 'paused' where id = '{AGENT}' returning status", OWNER, "paused")
denied("a paused agent stops mid-game",
       f"select agent_machine_session({signed('agent-session', {'key': sha(RAW), 'session': S['id']})})", ANON, "is paused")
value(f"update agents set status = 'active' where id = '{AGENT}'", OWNER)
ended = json.loads(allowed("the platform ends the session",
                           f"select agent_machine_end({signed('agent-end', {'key': sha(RAW), 'session': S['id'], 'result': 'win'})})", ANON))
check("...the end has no secret in it", "secret" not in ended and ended["status"] == "finished" and ended["result"] == "win")
denied("no moves after the end",
       f"select agent_machine_record({signed('agent-record', {'key': sha(RAW), 'session': S['id'], 'plies': 2, 'state': state})})",
       ANON, "has ended")

usage = value(f"select moves || ' ' || sessions from agent_usage where agent_id = '{AGENT}'", OWNER)
check("usage counts moves and sessions for the owner", usage == "3 1", usage)
check("others see none of it", value("select count(*) from agent_usage", OTHER) == "0")
value(f"select agent_machine_key({signed('agent-key', {'key': sha(RAW), 'gauge': True})})")
check("difficulty readings count against the account",
      value("select gauges from agent_usage where agent_id = '00000000-0000-0000-0000-000000000000'", OWNER) == "1")

# -----------------------------------------------------------------------------
# Revoking
# -----------------------------------------------------------------------------
denied("someone else cannot revoke your key", f"select revoke_agent_key('{KEY_ID}')", OTHER, "no such key")
allowed("the owner revokes it", f"select revoke_agent_key('{KEY_ID}')", OWNER, "")
denied("a revoked key stops at once",
       f"select agent_machine_key({signed('agent-key', {'key': sha(RAW)})})", ANON, "revoked")
denied("a revoked key cannot be brought back", f"update agent_keys set revoked_at = null where id = '{KEY_ID}'", OWNER)
allowed("deleting an agent takes its sessions with it",
        f"delete from agents where id = '{AGENT}' returning name", OWNER, "Ama B")
check("...gone", value(f"select count(*) from agent_sessions where agent_id = '{AGENT}'") == "0")

sys.exit(1 if report() else 0)
