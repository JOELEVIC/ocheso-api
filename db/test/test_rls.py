#!/usr/bin/env python3
"""
Acts as different people against db/schema.sql and asserts what each can do.

The schema puts authorisation in row level security, so this file is where that
authorisation is actually proven. Every check runs as a real Postgres role with
a JWT subject set - the same mechanism a request through PostgREST uses - not
as the superuser with a WHERE clause standing in for a policy.

Each of the four holes found in the old API has a check here by name, so a
regression reads as the bug it reintroduces rather than as a failed assertion.

    python3 db/test/test_rls.py [postgres-url]

Needs a database with db/test/supabase_shim.sql and db/schema.sql applied.
"""

from __future__ import annotations

import subprocess
import sys
import uuid

DB = sys.argv[1] if len(sys.argv) > 1 else "postgresql://postgres@127.0.0.1:55434/ocheso_test"

OWNER, COADMIN, MOD, PLAYER, STRANGER, P2, P3, P4 = (str(uuid.uuid4()) for _ in range(8))
ANON = "anon"

results: list[tuple[bool, str, str]] = []


def sql(statement: str, who: str | None = None) -> tuple[bool, str]:
    """Run as `who` (a user id, or ANON). None runs as the superuser, for setup."""
    prefix = ""
    if who == ANON:
        prefix = "set role anon; set request.jwt.claim.sub = '';"
    elif who is not None:
        prefix = f"set role authenticated; set request.jwt.claim.sub = '{who}';"
    proc = subprocess.run(
        ["psql", DB, "-v", "ON_ERROR_STOP=1", "-tAq", "-c", prefix + statement],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True, proc.stdout.strip()
    return False, proc.stderr.strip().splitlines()[0] if proc.stderr.strip() else "error"


def report() -> int:
    failed = [r for r in results if not r[0]]
    for passed, name, detail in results:
        print(f"{'ok  ' if passed else 'FAIL'}  {name}" + ("" if passed else f"\n      -> {detail}"))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return len(failed)


def value(statement: str) -> str:
    ok, out = sql(statement)
    if not ok:
        # Print what ran before stopping: a setup query fails because an earlier
        # check left the database in a state it did not expect, and that check
        # is the one worth reading.
        report()
        raise SystemExit(f"\nsetup query failed: {statement}\n{out}")
    return out


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append((passed, name, detail))


def allowed(name: str, statement: str, who: str, expect: str | None = None) -> str:
    ok, out = sql(statement, who)
    passed = ok and (expect is None or out == expect)
    check(name, passed, out if not passed else "")
    return out


def denied(name: str, statement: str, who: str) -> None:
    """Refused outright - a permission error or a raised exception."""
    ok, out = sql(statement, who)
    check(name, not ok, f"was allowed: {out!r}" if ok else "")


def no_effect(name: str, statement: str, who: str, probe: str, before: str) -> None:
    """Silently filtered by RLS: the statement runs, and nothing changes."""
    sql(statement, who)
    after = value(probe)
    check(name, after == before, f"changed: {before!r} -> {after!r}")


# -----------------------------------------------------------------------------
# Setup: people
# -----------------------------------------------------------------------------
value(
    "insert into auth.users (id, email, raw_user_meta_data) values "
    f"('{OWNER}', 'owner@ocheso.test', '{{\"full_name\":\"Ada Owner\"}}'),"
    f"('{COADMIN}', 'co@ocheso.test', '{{\"full_name\":\"Cole Admin\"}}'),"
    f"('{MOD}', 'mod@ocheso.test', '{{\"full_name\":\"Mo Derator\"}}'),"
    f"('{PLAYER}', 'player@ocheso.test', '{{\"full_name\":\"Pat Player\"}}'),"
    f"('{STRANGER}', 'stranger@ocheso.test', '{{\"full_name\":\"Sam Stranger\"}}'),"
    f"('{P2}', 'p2@ocheso.test', '{{}}'),"
    f"('{P3}', 'p3@ocheso.test', '{{}}'),"
    f"('{P4}', 'p4@ocheso.test', '{{}}')"
)

# -----------------------------------------------------------------------------
# What PostgREST can reach
# -----------------------------------------------------------------------------
# Supabase exposes the public schema as RPC. Role checks must not be in it.
check(
    "role-check helpers are not in public, so they are not API endpoints",
    value("select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
          "where n.nspname = 'public' and p.proname in ('is_tournament_owner', 'is_tournament_manager', "
          "'is_tournament_staff', 'is_tournament_participant', 'roster_is_public')") == "0",
)
check(
    "no public function an anonymous visitor can call except the two read paths",
    value("select string_agg(p.proname, ',' order by p.proname) from pg_proc p "
          "join pg_namespace n on n.oid = p.pronamespace "
          "where n.nspname = 'public' and p.prorettype <> 'trigger'::regtype "
          "and has_function_privilege('anon', p.oid, 'execute')") == "get_roster,get_tournament",
    value("select string_agg(p.proname, ',' order by p.proname) from pg_proc p "
          "join pg_namespace n on n.oid = p.pronamespace "
          "where n.nspname = 'public' and p.prorettype <> 'trigger'::regtype "
          "and has_function_privilege('anon', p.oid, 'execute')"),
)

# -----------------------------------------------------------------------------
# Profiles
# -----------------------------------------------------------------------------
check(
    "every new account gets a profile",
    value("select count(*) from profiles") == "8",
)
check(
    "display name comes from the sign-up metadata",
    value(f"select display_name from profiles where id = '{OWNER}'") == "Ada Owner",
)
check(
    "no email anywhere a stranger can read it (profiles has no email column)",
    value("select count(*) from information_schema.columns where table_name = 'profiles' and column_name = 'email'") == "0",
)
allowed("anyone can read profiles", "select count(*) from profiles", ANON, "8")
denied(
    "OLD BUG 9 - a player cannot set their own rating",
    f"update profiles set chess_rating = 2800 where id = '{PLAYER}'",
    PLAYER,
)
allowed(
    "a player can change their own display name",
    f"update profiles set display_name = 'Pat P.' where id = '{PLAYER}' returning display_name",
    PLAYER,
    "Pat P.",
)
no_effect(
    "a player cannot edit somebody else's profile",
    f"update profiles set display_name = 'hacked' where id = '{STRANGER}'",
    PLAYER,
    f"select display_name from profiles where id = '{STRANGER}'",
    "Sam Stranger",
)

check(
    "every account is given a username, so staff can be added by name",
    value(f"select username from profiles where id = '{PLAYER}'").startswith("player_"),
)
allowed("me() returns the caller's own profile", "select display_name from me()", PLAYER, "Pat P.")
denied("me() is not available to anonymous visitors", "select * from me()", ANON)

# -----------------------------------------------------------------------------
# Creating a tournament
# -----------------------------------------------------------------------------
CREATE = (
    "insert into tournaments (title, game, variant, format, clock_base_s, clock_increment_s, "
    "starts_at, rounds_count) values ('Saturday Rapid', 'chess', 'standard', 'swiss', 600, 5, "
    "now() + interval '7 days', 5) returning id"
)
TID = allowed("a signed-in user can create a tournament (and read it back)", CREATE, OWNER)
check(
    "OLD BUG 6 - the creator is the owner, without being told",
    value(f"select owner_id from tournaments where id = '{TID}'") == OWNER,
)
SLUG = value(f"select slug from tournaments where id = '{TID}'")
check("a slug is generated from the title", SLUG.startswith("saturday-rapid-"), SLUG)
check("new tournaments start as drafts", value(f"select status from tournaments where id = '{TID}'") == "draft")
check(
    "an invite token is created with every tournament",
    value(f"select length(invite_token) from tournament_secrets where tournament_id = '{TID}'") == "32",
)
denied("anonymous visitors cannot create tournaments", CREATE, ANON)
denied(
    "nobody can create a tournament in someone else's name",
    "insert into tournaments (owner_id, title, game, variant, format, clock_base_s, starts_at, rounds_count) "
    f"values ('{STRANGER}', 'Forged', 'chess', 'standard', 'swiss', 600, now(), 5)",
    OWNER,
)
denied(
    "chess cannot be given a checkers variant",
    "insert into tournaments (title, game, variant, format, clock_base_s, starts_at, rounds_count) "
    "values ('Mixed up', 'chess', 'brazilian', 'swiss', 600, now(), 5)",
    OWNER,
)

# -----------------------------------------------------------------------------
# Drafts are private
# -----------------------------------------------------------------------------
allowed("the owner sees their draft", f"select count(*) from tournaments where id = '{TID}'", OWNER, "1")
allowed("a stranger cannot see a draft", f"select count(*) from tournaments where id = '{TID}'", STRANGER, "0")
allowed("an anonymous visitor cannot see a draft", f"select count(*) from tournaments where id = '{TID}'", ANON, "0")
allowed("get_tournament() hides drafts from strangers too", f"select count(*) from get_tournament('{SLUG}') where id is not null", STRANGER, "0")

# -----------------------------------------------------------------------------
# Editing, deleting, taking over
# -----------------------------------------------------------------------------
TITLE_PROBE = f"select title from tournaments where id = '{TID}'"
no_effect(
    "OLD BUG 2 - a stranger cannot edit someone else's tournament",
    f"update tournaments set title = 'Taken' where id = '{TID}'",
    STRANGER,
    TITLE_PROBE,
    "Saturday Rapid",
)
no_effect(
    "OLD BUG 2 - a stranger cannot delete someone else's tournament",
    f"delete from tournaments where id = '{TID}'",
    STRANGER,
    f"select count(*) from tournaments where id = '{TID}'",
    "1",
)
denied(
    "even the owner cannot hand ownership away by UPDATE",
    f"update tournaments set owner_id = '{STRANGER}' where id = '{TID}'",
    OWNER,
)
denied(
    "status cannot be set directly - only through set_tournament_status()",
    f"update tournaments set status = 'live' where id = '{TID}'",
    OWNER,
)
allowed(
    "the owner can edit their tournament",
    f"update tournaments set title = 'Saturday Rapid Cup' where id = '{TID}' returning title",
    OWNER,
    "Saturday Rapid Cup",
)

# -----------------------------------------------------------------------------
# Secrets
# -----------------------------------------------------------------------------
allowed("the owner can set an entry code", f"update tournament_secrets set entry_code = 'OCH7K2' where tournament_id = '{TID}' returning entry_code", OWNER, "OCH7K2")
denied("OLD BUG 7 - an anonymous visitor cannot read entry codes", "select entry_code from tournament_secrets", ANON)
allowed("OLD BUG 7 - a stranger cannot read entry codes", "select count(*) from tournament_secrets where entry_code is not null", STRANGER, "0")
check(
    "OLD BUG 7 - the entry code is not a column of the public tournament row",
    value("select count(*) from information_schema.columns where table_name = 'tournaments' and column_name = 'entry_code'") == "0",
)
denied(
    "OLD BUG 1 - there is no route to read an arbitrary table as anon",
    "select * from tournament_secrets",
    ANON,
)

# -----------------------------------------------------------------------------
# Staff
# -----------------------------------------------------------------------------
denied(
    "OLD BUG 3 - a stranger cannot make themselves an admin",
    f"insert into tournament_admins (tournament_id, user_id, role) values ('{TID}', '{STRANGER}', 'co_admin')",
    STRANGER,
)
allowed(
    "the owner appoints a co-admin",
    f"insert into tournament_admins (tournament_id, user_id, role) values ('{TID}', '{COADMIN}', 'co_admin') returning role",
    OWNER,
    "co_admin",
)
allowed(
    "the owner appoints a moderator",
    f"insert into tournament_admins (tournament_id, user_id, role) values ('{TID}', '{MOD}', 'moderator') returning role",
    OWNER,
    "moderator",
)
denied(
    "a co-admin cannot appoint further staff",
    f"insert into tournament_admins (tournament_id, user_id, role) values ('{TID}', '{STRANGER}', 'moderator')",
    COADMIN,
)
allowed("a co-admin can edit settings", f"update tournaments set description = 'Five rounds' where id = '{TID}' returning description", COADMIN, "Five rounds")
allowed("a co-admin can see the entry code", f"select entry_code from tournament_secrets where tournament_id = '{TID}'", COADMIN, "OCH7K2")
no_effect(
    "a moderator cannot edit settings",
    f"update tournaments set title = 'Mod was here' where id = '{TID}'",
    MOD,
    TITLE_PROBE,
    "Saturday Rapid Cup",
)
allowed("a moderator cannot see the entry code", f"select count(*) from tournament_secrets where tournament_id = '{TID}'", MOD, "0")
allowed("a moderator can see the draft they help run", f"select count(*) from tournaments where id = '{TID}'", MOD, "1")

# -----------------------------------------------------------------------------
# Lifecycle
# -----------------------------------------------------------------------------
denied("a stranger cannot publish someone else's tournament", f"select set_tournament_status('{TID}', 'registration')", STRANGER)
denied("a moderator cannot publish", f"select set_tournament_status('{TID}', 'registration')", MOD)
denied("a draft cannot jump straight to finished", f"select set_tournament_status('{TID}', 'finished')", OWNER)
allowed("the owner publishes", f"select status from set_tournament_status('{TID}', 'registration')", OWNER, "registration")
allowed("published and listed: anonymous visitors can see it", f"select count(*) from tournaments where id = '{TID}'", ANON, "1")
no_effect(
    "only drafts can be deleted - a published event keeps its record",
    f"delete from tournaments where id = '{TID}'",
    OWNER,
    f"select count(*) from tournaments where id = '{TID}'",
    "1",
)

# -----------------------------------------------------------------------------
# Joining: open entry
# -----------------------------------------------------------------------------
denied(
    "OLD BUG 8 - nobody can insert a participant row directly",
    f"insert into participants (tournament_id, user_id, status) values ('{TID}', '{PLAYER}', 'approved')",
    PLAYER,
)
denied("anonymous visitors cannot join", f"select join_tournament('{SLUG}')", ANON)

# Open the gate: no code, auto-approve, so the first joins are straightforward.
value(f"update tournaments set requires_code = false, auto_approve = true where id = '{TID}'")
allowed(
    "OLD BUG 8 - joining records the caller, whoever the body claims",
    f"select user_id from join_tournament('{SLUG}')",
    PLAYER,
    PLAYER,
)
check(
    "open entry with auto-approve is approved at once",
    value(f"select status from participants where tournament_id = '{TID}' and user_id = '{PLAYER}'") == "approved",
)
check(
    "the rating at entry is snapshotted",
    value(f"select rating_at_entry from participants where tournament_id = '{TID}' and user_id = '{PLAYER}'") == "1500",
)
allowed(
    "joining twice returns the existing entry instead of failing",
    f"select count(*) from join_tournament('{SLUG}')",
    PLAYER,
    "1",
)

# -----------------------------------------------------------------------------
# Joining: entry code
# -----------------------------------------------------------------------------
value(f"update tournaments set requires_code = true, auto_approve = false where id = '{TID}'")
denied("a code-only event refuses entry with no code", f"select join_tournament('{SLUG}')", P2)
denied("a code-only event refuses the wrong code", f"select join_tournament('{SLUG}', 'WRONG1')", P2)
allowed(
    "the right code admits, into the approval queue when auto-approve is off",
    f"select status from join_tournament('{SLUG}', 'och7k2')",
    P2,
    "pending",
)

# -----------------------------------------------------------------------------
# Joining: invite link
# -----------------------------------------------------------------------------
TOKEN = value(f"select invite_token from tournament_secrets where tournament_id = '{TID}'")
allowed(
    "an invite link admits straight in, past both code and queue",
    f"select status || '/' || joined_via from join_tournament('{SLUG}', null, '{TOKEN}')",
    P3,
    "approved/invite",
)
NEW_TOKEN = allowed("the owner can rotate the invite link", f"select rotate_invite('{TID}')", OWNER)
check("rotating produces a new token", NEW_TOKEN not in ("", TOKEN))
denied("the old invite link stops working once rotated", f"select join_tournament('{SLUG}', null, '{TOKEN}')", P4)
denied("a stranger cannot rotate the invite link", f"select rotate_invite('{TID}')", STRANGER)

# -----------------------------------------------------------------------------
# Approving
# -----------------------------------------------------------------------------
PENDING = value(f"select id from participants where tournament_id = '{TID}' and user_id = '{P2}'")
denied("a stranger cannot approve entries", f"select decide_participant('{PENDING}', 'approved')", STRANGER)
denied("a player cannot approve their own entry", f"select decide_participant('{PENDING}', 'approved')", P2)
denied("entries can only be approved or rejected, not withdrawn by staff", f"select decide_participant('{PENDING}', 'withdrawn')", MOD)
allowed("a moderator can approve an entry", f"select status from decide_participant('{PENDING}', 'approved')", MOD, "approved")
check(
    "the approval records who made it",
    value(f"select decided_by from participants where id = '{PENDING}'") == MOD,
)

# -----------------------------------------------------------------------------
# Capacity
# -----------------------------------------------------------------------------
value(f"update tournaments set max_participants = 3, requires_code = false, auto_approve = true where id = '{TID}'")
denied("a full tournament refuses another entry", f"select join_tournament('{SLUG}')", P4)

# -----------------------------------------------------------------------------
# Who can see the roster
# -----------------------------------------------------------------------------
allowed("visitors see the approved roster", f"select count(*) from get_roster('{SLUG}')", ANON, "3")
allowed("the roster carries names", f"select display_name from get_roster('{SLUG}') where user_id = '{PLAYER}'", ANON, "Pat P.")
value(f"update tournaments set participants_visible = false where id = '{TID}'")
allowed("a hidden roster is hidden from visitors", f"select count(*) from get_roster('{SLUG}')", ANON, "0")
allowed("participants still see a hidden roster", f"select count(*) from get_roster('{SLUG}')", PLAYER, "3")
allowed("staff still see a hidden roster", f"select count(*) from get_roster('{SLUG}')", MOD, "3")
value(f"update tournaments set participants_visible = true where id = '{TID}'")

# -----------------------------------------------------------------------------
# Unlisted means reachable by link, not by search
# -----------------------------------------------------------------------------
value(f"update tournaments set is_listed = false where id = '{TID}'")
allowed("an unlisted event does not appear in listings", f"select count(*) from tournaments where id = '{TID}'", ANON, "0")
allowed("an unlisted event's roster is not enumerable", f"select count(*) from participants where tournament_id = '{TID}'", ANON, "0")
allowed("an unlisted event is reachable by its slug", f"select title from get_tournament('{SLUG}')", ANON, "Saturday Rapid Cup")
value(f"update tournaments set is_listed = true where id = '{TID}'")

# -----------------------------------------------------------------------------
# Withdrawing
# -----------------------------------------------------------------------------
allowed("a player can withdraw before the start", f"select status from withdraw_from_tournament('{SLUG}')", P3, "withdrawn")
allowed("withdrawing frees the seat for someone else", f"select status from join_tournament('{SLUG}')", P4, "approved")
allowed("the owner starts the event", f"select status from set_tournament_status('{TID}', 'live')", OWNER, "live")
denied("nobody can withdraw once the event is live", f"select withdraw_from_tournament('{SLUG}')", PLAYER)
denied("nobody can join once the event is live", f"select join_tournament('{SLUG}')", STRANGER)
denied("a live event cannot go back to registration", f"select set_tournament_status('{TID}', 'registration')", OWNER)

# -----------------------------------------------------------------------------
# my_tournaments()
# -----------------------------------------------------------------------------
allowed("the owner's list names them owner", f"select my_role from my_tournaments() where (tournament).id = '{TID}'", OWNER, "owner")
allowed("a co-admin's list names them co_admin", f"select my_role from my_tournaments() where (tournament).id = '{TID}'", COADMIN, "co_admin")
allowed("a player's list names them participant", f"select my_role from my_tournaments() where (tournament).id = '{TID}'", PLAYER, "participant")
allowed("a stranger's list does not include it", f"select count(*) from my_tournaments() where (tournament).id = '{TID}'", STRANGER, "0")

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------
sys.exit(1 if report() else 0)
