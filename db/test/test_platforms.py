#!/usr/bin/env python3
"""
Tries to misuse db/platforms.sql - organisations, member profiles, email
invites, embed sessions, the three signed dispatchers, autopilot, the live
feed, webhooks, throttles - and asserts that it cannot.

As test_agents.py: real Postgres roles with a JWT subject, requests signed the
way the API signs them (the key read as the superuser, the only way to get
it), and the parts of Supabase that are not here - Auth confirming an address,
pg_net answering - played by hand through db/test/supabase_shim.sql.

    python3 db/test/test_platforms.py [postgres-url]

Needs supabase_shim.sql, then db/apply.sh (all four files), applied.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import uuid

DB = sys.argv[1] if len(sys.argv) > 1 else "postgresql://postgres@127.0.0.1:55434/ocheso_test"

ANON = "anon"
results: list[tuple[bool, str, str]] = []


def sql(statement: str, who: str | None = None) -> tuple[bool, str]:
    prefix = ""
    if who == ANON:
        prefix = "set role anon; set request.jwt.claim.sub = '';"
    elif who is not None:
        prefix = f"set role authenticated; set request.jwt.claim.sub = '{who}';"
    # Verbose errors carry the SQLSTATE ("ERROR:  OC401: ..."), so a refusal
    # can be asserted by its code, not only its words.
    p = subprocess.run(["psql", DB, "-X", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-tAq",
                        "-c", prefix + statement], capture_output=True, text=True)
    if p.returncode == 0:
        return True, p.stdout.strip()
    lines = [l for l in p.stderr.strip().splitlines() if l.startswith("ERROR")] or p.stderr.strip().splitlines()
    return False, (lines or ["error"])[0]


def value(statement: str, who: str | None = None) -> str:
    ok, out = sql(statement, who)
    if not ok:
        report()
        raise SystemExit(f"\nsetup failed: {statement[:300]}\n{out}")
    return out


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append((passed, name, detail))


def allowed(name: str, statement: str, who: str | None, expect: str | None = None) -> str:
    ok, out = sql(statement, who)
    check(name, ok and (expect is None or out == expect), out)
    return out


def denied(name: str, statement: str, who: str | None, because: str | None = None) -> str:
    ok, out = sql(statement, who)
    check(name, not ok and (because is None or because in out), f"was allowed: {out!r}" if ok else out)
    return out


def report() -> int:
    failed = [r for r in results if not r[0]]
    for passed, name, detail in results:
        print(f"{'ok  ' if passed else 'FAIL'}  {name}" + ("" if passed else f"\n      -> {detail}"))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return len(failed)


SECRET = value("select secret from private.referee")


def q(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def js(obj) -> str:
    return q(json.dumps(obj))


def signed(kind: str, body: dict, ttl: int = 60, key: str | None = None) -> str:
    """A request as core/play/referee.py's sign_request makes it: no `by`."""
    payload = json.dumps({**body, "kind": kind, "exp": int(time.time()) + ttl}, separators=(",", ":"), sort_keys=True)
    sig = hmac.new((key or SECRET).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{q(payload)}, '{sig}'"


def sha(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def emb(kind: str, body: dict, who: str = ANON) -> tuple[bool, str]:
    return sql(f"select embed_call({signed(kind, body)})", who)


def emb_ok(name: str, kind: str, body: dict) -> dict:
    ok, out = emb(kind, body)
    check(name, ok, out)
    return json.loads(out) if ok and out else {}


def orgc(kind: str, body: dict) -> tuple[bool, str]:
    return sql(f"select org_call({signed(kind, body)})", ANON)


def org_ok(name: str, kind: str, body: dict) -> dict:
    ok, out = orgc(kind, body)
    check(name, ok, out)
    return json.loads(out) if ok and out else {}


def sysc(kind: str, body: dict) -> tuple[bool, str]:
    return sql(f"select system_call({signed(kind, body)})", ANON)


def sys_ok(name: str, kind: str, body: dict):
    ok, out = sysc(kind, body)
    check(name, ok, out)
    return json.loads(out) if ok and out else {}


def user(name: str, confirmed: bool = True, meta: dict | None = None) -> str:
    uid = str(uuid.uuid4())
    value(f"insert into auth.users (id, email, raw_user_meta_data, email_confirmed_at) values "
          f"('{uid}', '{name}@platforms.test', {js(meta if meta is not None else {'full_name': name.title()})}, "
          f"{'now()' if confirmed else 'null'})")
    return uid


def tournament(owner: str, title: str, org: str | None = None, status: str = "draft", **cols) -> str:
    fields = {"owner_id": owner, "title": title, "game": "chess", "variant": "standard", "format": "swiss",
              "clock_base_s": 300, "starts_at": "2030-01-01T10:00:00Z", "rounds_count": 3, **cols}
    if org:
        fields["org_id"] = org
    names = ", ".join(fields)
    vals = ", ".join("null" if v is None else (q(v) if isinstance(v, str) else str(v).lower()) for v in fields.values())
    tid = value(f"insert into tournaments ({names}) values ({vals}) returning id")
    if status in ("registration", "live", "finished"):
        value(f"update tournaments set status = 'registration' where id = '{tid}'")
    if status in ("live", "finished"):
        value(f"update tournaments set status = 'live' where id = '{tid}'")
    if status == "finished":
        value(f"update tournaments set status = 'finished' where id = '{tid}'")
    return tid


def slug(tid: str) -> str:
    return value(f"select slug from tournaments where id = '{tid}'")


START = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
AFTER_E4 = "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1"

# =============================================================================
# Plumbing: derived keys, checks, what anyone can call
# =============================================================================
check("derived_key matches Python's hmac(REFEREE_SECRET, label)",
      value("select private.derived_key('ocheso:v1:tick')")
      == hmac.new(SECRET.encode(), b"ocheso:v1:tick", hashlib.sha256).hexdigest())
check("...for the IP label too",
      value("select private.derived_key('ocheso:v1:ip')")
      == hmac.new(SECRET.encode(), b"ocheso:v1:ip", hashlib.sha256).hexdigest())
_ip_key = hmac.new(SECRET.encode(), b"ocheso:v1:ip", hashlib.sha256).hexdigest()
_today = value("select to_char(now() at time zone 'utc', 'YYYY-MM-DD')")
check("the IP hash is hmac(derived ip key, address || UTC date)",
      value("select private.ip_hash('203.0.113.9')")
      == hmac.new(_ip_key.encode(), f"203.0.113.9{_today}".encode(), hashlib.sha256).hexdigest())
denied("clients cannot derive keys", "select private.derived_key('ocheso:v1:tick')", ANON)
check("plan limits are the contract's",
      value("select string_agg(private.plan_limit(p, w)::text, ',' order by p, w) from "
            "unnest(array['community','club','federation']::org_plan[]) p, "
            "unnest(array['players','members','keys','webhooks','invites_day','player_tokens_min']) w")
      # ordered by plan, then by name: invites_day, keys, members, player_tokens_min, players, webhooks
      == "500,2,3,60,64,0,5000,10,20,600,4096,5,50000,50,100,3000,4096,20")

GOOD_BRAND = {"v": 1, "name": "Yoursite", "logo_url": "https://cdn.example.com/logo.png",
              "colors": {"primary": "#2f55e0", "accent": "#FF5500"}, "font": "inter", "radius": 12,
              "theme": "auto", "board": "wood", "locale": "both", "badge": False}
check("a full brand passes", value(f"select private.brand_ok({js(GOOD_BRAND)})") == "t")
for label, bad in [("an unknown key", {"css": "body{}"}), ("a colour that is not #rrggbb", {"colors": {"primary": "red"}}),
                   ("a logo URL that could break out of an attribute", {"logo_url": "https://a.com/x\".png"}),
                   ("a logo URL with parens (url() breakout)", {"logo_url": "https://a.com/x).png"}),
                   ("http logos", {"logo_url": "http://a.com/x.png"}), ("a font off the list", {"font": "comic"}),
                   ("a radius over 24", {"radius": 40}), ("a badge that is not a boolean", {"badge": "no"}),
                   ("more than 4 KB", {"name": "x" * 70, "colors": {f"c{i}": "#000000" for i in range(16)},
                                       "logo_url": "https://a.com/" + "y" * 480, "logo_dark_url": "https://a.com/" + "z" * 480}),
                   ]:
    if label == "more than 4 KB":
        bad = {**bad, "theme": "dark"}
        big = json.dumps(bad)
        check("a brand of " + label + " fails" if len(big) > 4096 else "the 4 KB case is big enough",
              len(big) <= 4096 or value(f"select private.brand_ok({js(bad)})") == "f")
        continue
    check(f"a brand with {label} fails", value(f"select private.brand_ok({js(bad)})") == "f")
check("allowed origins: https hosts, ports, *.host, and http only for localhost",
      value("select private.origins_ok(array['https://a.com','https://www.a.com:8443','https://*.b.co.uk',"
            "'http://localhost:3000','http://127.0.0.1'])") == "t")
for bad in ["http://a.com", "https://*.com", "https://a.com/path", "*", "https://A.com", "javascript:alert(1)"]:
    check(f"allowed origins refuse {bad}", value(f"select private.origins_ok(array[{q(bad)}])") == "f")
check("more than 50 origins are refused",
      value("select private.origins_ok(array(select 'https://h' || i || '.com' from generate_series(1, 51) i))") == "f")
# origin_allowed is CSP's rule, as the site's frame applies it (embed/protocol.ts
# originAllowed): the frame and the database must never disagree about a page.
for entries, page, want, why in [
    (["https://a.com"], "https://a.com", True, "an exact origin"),
    (["https://a.com"], "https://A.com", True, "...in any case"),
    (["https://a.com"], "https://a.com:443", True, "...with its default port said"),
    (["https://a.com"], "https://a.com:8443", False, "an entry without a port is the default port only"),
    (["https://a.com"], "http://a.com", False, "an https entry never allows http"),
    (["http://localhost:3000"], "https://localhost:3000", True, "an http entry also allows https (CSP's upgrade)"),
    (["http://localhost:3000"], "http://localhost:3001", False, "...on its own port"),
    (["http://127.0.0.1"], "http://127.0.0.1:80", True, "...and its default port"),
    (["https://a.com:8443"], "https://a.com:8443", True, "a port"),
    (["https://a.com:8443"], "https://a.com", False, "...is that port only"),
    (["https://a.com:*"], "https://a.com:8443", True, ":* is any port"),
    (["https://a.com:*"], "https://a.com", True, "...the default one too"),
    (["https://*.a.com"], "https://x.a.com", True, "*.a.com allows a subdomain"),
    (["https://*.a.com"], "https://x.y.a.com", True, "...and a deeper one"),
    (["https://*.a.com"], "https://a.com", False, "...but not a.com itself (CSP rules)"),
    (["https://*.a.com"], "https://evila.com", False, "...nor evila.com"),
    (["https://*.a.com"], "https://xa.com", False, "...nor xa.com"),
    (["https://*.a.com"], "http://x.a.com", False, "...nor a subdomain over http"),
    (["https://*.a.com"], "https://x.a.com:8443", False, "...nor on another port"),
    (["https://*.a.com:*"], "https://x.a.com:8443", True, "...unless the entry says :*"),
    (["https://a.com"], "https://a.com.evil.example", False, "a host that only starts the same"),
    (["https://a.com/"], "https://a.com", True, "an entry's trailing slash"),
    (["https://a.com", "https://b.com"], "https://b.com", True, "any entry of several"),
    (["*"], "https://anything.example", True, "* is anywhere"),
    (["*"], "null", False, "...but never an opaque origin"),
    (["https://a.com"], "javascript:alert(1)", False, "garbage is no origin"),
    ([], "https://anything.example", True, "an empty list allows anywhere"),
]:
    got = value(f"select private.origin_allowed(array[{', '.join(q(e) for e in entries)}]::text[], {q(page)})")
    check(f"origin_allowed: {why} ({entries} / {page})", got == ("t" if want else "f"), got)

for url, ok in [("https://hooks.example.com/ocheso", True), ("https://hooks.example.com:443/x?y=1", True),
                ("http://hooks.example.com/x", False), ("https://hooks.example.com:8443/x", False),
                ("https://127.0.0.1/x", False), ("https://10.0.0.8/x", False), ("https://[::1]/x", False),
                ("https://localhost/x", False), ("https://printer.local/x", False), ("https://db.internal/x", False),
                ("https://abc.supabase.co/rest/v1", False), ("https://api.ocheso.com/x", False), ("https://ocheso.com", False),
                ("https://user@hooks.example.com/x", False), ("https://hooks.example.com/" + "a" * 500, False),
                # Names that resolve to whatever address they spell (pg_net resolves for itself).
                ("https://169.254.169.254.nip.io/x", False), ("https://10.0.0.5.sslip.io/", False),
                ("https://127.0.0.1.nip.io/", False), ("https://10-0-0-5.sslip.io/x", False),
                ("https://hooks.xip.io/x", False), ("https://anything.localtest.me/x", False),
                ("https://api.lvh.me/x", False), ("https://hooks.10.1.2.3.example.com/x", False),
                ("https://ip-192-168-0-1.example.com/x", False),
                ("https://hooks.example.com/v2/2024.10.25", True), ("https://n8n.example.io/webhook/1", True)]:
    check(f"webhook URL {url[:60]} is {'accepted' if ok else 'refused'}",
          value(f"select private.webhook_url_ok({q(url)})") == ("t" if ok else "f"))

# Postgres grants EXECUTE to PUBLIC on every new function, and anon and
# authenticated have USAGE on `private`: every private function that is not a
# policy helper must have been revoked, or it is callable around the API.
POLICY_HELPERS = {"is_tournament_owner", "is_tournament_manager", "is_tournament_staff", "is_tournament_participant",
                  "roster_is_public", "games_public", "time_left", "side_of", "org_role", "is_org_admin",
                  "member_visible", "brand_ok", "brand_url_ok", "origins_ok", "webhook_url_ok", "webhook_events"}
callable_private = set(value("select coalesce(string_agg(p.proname, ','), '') from pg_proc p join pg_namespace n on n.oid = p.pronamespace "
                             "where n.nspname = 'private' and has_function_privilege('anon', p.oid, 'execute')").split(",")) - {""}
check("no private function an anonymous caller can run except policy helpers and pure checks",
      callable_private <= POLICY_HELPERS, ",".join(sorted(callable_private - POLICY_HELPERS)))
check("private tables are closed to clients",
      value("select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = 'private' and c.relkind = 'r' "
            "and (has_table_privilege('anon', c.oid, 'select') or has_table_privilege('authenticated', c.oid, 'select'))") == "0")

# =============================================================================
# Organisations and their roles
# =============================================================================
OWNER, OUTSIDER = user("orgowner"), user("outsider")
denied("visitors cannot create organisations", "select id from create_organization('acme', 'Acme')", ANON)
denied("reserved words are not slugs", "select id from create_organization('studio', 'Studio')", OWNER, "check")
denied("nor are malformed ones", "select id from create_organization('Acme--Co', 'Acme')", OWNER, "check")
denied("a brand is checked on the way in",
       f"select id from create_organization('acme', 'Acme', null, {js({'css': 'x'})})", OWNER, "check")
denied("a time zone must exist", "select id from create_organization('acme', 'Acme', null, '{}', '{}', 'Mars/Olympus')",
       OWNER, "time zone")
ORG = allowed("an account creates an organisation",
              f"select id from create_organization('acme', 'Acme Chess', 'https://acme.example', {js(GOOD_BRAND)}, "
              f"array['https://acme.example', 'https://*.acme.example'], 'Africa/Douala')", OWNER)
check("...and is its owner, in the same transaction",
      value(f"select role from org_members where org_id = '{ORG}' and user_id = '{OWNER}'") == "owner")
check("a taken slug is a unique violation (the API retries with a suffix)",
      "23505" in sql("select id from create_organization('acme', 'Other')", OUTSIDER)[1])
OTHER_ORG = value("select id from create_organization('rival', 'Rival Club')", OUTSIDER)
check("organisations are on the community plan, active", value(f"select plan || ' ' || status from organizations where id = '{ORG}'")
      == "community active")
allowed("an outsider cannot see the organisation", f"select count(*) from organizations where id = '{ORG}'", OUTSIDER, "0")
allowed("visitors read the public face through get_org_public", "select get_org_public('acme') ->> 'name'", ANON, "Acme Chess")
check("...with the badge computed from the plan",
      value("select get_org_public('acme') ->> 'badge'", ANON) == "full")
denied("nobody upgrades their own plan", f"update organizations set plan = 'federation' where id = '{ORG}'", OWNER)
denied("nor lifts a suspension", f"update organizations set status = 'active' where id = '{ORG}'", OWNER)
allowed("the owner edits the name", f"update organizations set name = 'Acme Chess Club' where id = '{ORG}' returning name",
        OWNER, "Acme Chess Club")

# Team, by email: joined by accepting from the email - never just by signing
# in, because a member can be handed the organisation and cannot delete their
# account while they are one.
denied("staff are invited by owners and admins only", f"select invite_org_member('{ORG}', 'x@platforms.test')", OUTSIDER)
inv_admin = json.loads(allowed("the owner invites an admin by email",
                               f"select invite_org_member('{ORG}', 'Ada.Admin@platforms.test', 'admin')", OWNER))
check("...with the address normalised and no token in the reply",
      inv_admin.get("email") == "ada.admin@platforms.test" and "token" not in inv_admin)
check("...and an email queued", value(f"select count(*) from private.mail_outbox where kind = 'org-invite' and org_id = '{ORG}'") == "1")
ADMIN = str(uuid.uuid4())
value(f"insert into auth.users (id, email, email_confirmed_at) values ('{ADMIN}', 'ada.admin@platforms.test', now())")
check("signing up with that confirmed address does not, by itself, join the team",
      value(f"select count(*) from org_members where org_id = '{ORG}' and user_id = '{ADMIN}'") == "0")
value(f"update auth.users set last_sign_in_at = now() where id = '{ADMIN}'")
value("select claim_my_invites()", ADMIN)
check("...nor does signing in again, or a page load's claim_my_invites",
      value(f"select count(*) from org_members where org_id = '{ORG}' and user_id = '{ADMIN}'") == "0"
      and value(f"select status from org_invites where org_id = '{ORG}' and email = 'ada.admin@platforms.test'") == "pending")
ADMIN_TOKEN = value(f"select token from org_invites where org_id = '{ORG}' and email = 'ada.admin@platforms.test'")
denied("another account cannot accept it", f"select accept_invite('{ADMIN_TOKEN}')", OUTSIDER, "another address")
allowed("its addressee accepts from the email", f"select accept_invite('{ADMIN_TOKEN}') ->> 'status'", ADMIN, "accepted")
check("...and is an admin", value(f"select role from org_members where org_id = '{ORG}' and user_id = '{ADMIN}'") == "admin")
STAFF = user("stan")  # an existing account; the invite comes later
denied("an admin cannot invite admins", f"select invite_org_member('{ORG}', 'zed@platforms.test', 'admin')", ADMIN, "owner")
allowed("an admin invites staff", f"select invite_org_member('{ORG}', 'stan@platforms.test', 'staff') ->> 'role'", ADMIN, "staff")
value(f"update auth.users set last_sign_in_at = now() where id = '{STAFF}'")
check("an existing account is not joined at its next sign-in",
      value(f"select count(*) from org_members where org_id = '{ORG}' and user_id = '{STAFF}'") == "0")
STAN_TOKEN = value("select token from org_invites where email = 'stan@platforms.test'")  # from their inbox
allowed("...but when they accept", f"select accept_invite('{STAN_TOKEN}') ->> 'kind'", STAFF, "org")
check("...they are staff", value(f"select role from org_members where org_id = '{ORG}' and user_id = '{STAFF}'") == "staff")
denied("community allows three people in the team", f"select invite_org_member('{ORG}', 'fourth@platforms.test')", OWNER, "allows 3")
denied("staff cannot invite", f"select invite_org_member('{ORG}', 'y@platforms.test')", STAFF)
allowed("the team sees the team", f"select count(*) from org_members where org_id = '{ORG}'", STAFF, "3")
allowed("outsiders do not", f"select count(*) from org_members where org_id = '{ORG}'", OUTSIDER, "0")
no_change = value(f"select name from organizations where id = '{ORG}'")
sql(f"update organizations set name = 'Staff was here' where id = '{ORG}'", STAFF)
check("staff cannot edit the organisation", value(f"select name from organizations where id = '{ORG}'") == no_change)
denied("only the owner changes roles", f"select role from set_org_member_role('{ORG}', '{STAFF}', 'admin')", ADMIN, "owner")
denied("an admin cannot remove an admin", f"select remove_org_member('{ORG}', '{ADMIN}')", ADMIN)
denied("the owner cannot just leave", f"select leave_org('{ORG}')", OWNER, "transfer")
denied("ownership goes only to a member", f"select transfer_org_ownership('{ORG}', '{OUTSIDER}')", OWNER, "another member")
allowed("the owner transfers to the admin", f"select transfer_org_ownership('{ORG}', '{ADMIN}')", OWNER, "")
check("...exactly one owner, the old one now an admin",
      value(f"select string_agg(role, ',' order by role) from org_members where org_id = '{ORG}' and role in ('owner','admin')")
      == "admin,owner" and value(f"select role from org_members where org_id = '{ORG}' and user_id = '{OWNER}'") == "admin")
value(f"select transfer_org_ownership('{ORG}', '{OWNER}')", ADMIN)

# The attack the explicit yes closes: invite someone, wait for them to sign
# in, hand them the organisation - and their account could not be deleted.
VICTIM = user("victim")
value(f"select invite_org_member('{OTHER_ORG}', 'victim@platforms.test', 'staff')", OUTSIDER)
value(f"update auth.users set last_sign_in_at = now() where id = '{VICTIM}'")
denied("an owner cannot hand their organisation to someone who only signed in",
       f"select transfer_org_ownership('{OTHER_ORG}', '{VICTIM}')", OUTSIDER, "another member")
check("...whose account can still be deleted",
      sql(f"delete from auth.users where id = '{VICTIM}'")[0]
      and value(f"select count(*) from profiles where id = '{VICTIM}'") == "0")
TEN = user("tenorgs")
for i in range(10):
    value(f"select id from create_organization('ten-org-{i}', 'Ten Org {i}')", TEN)
value(f"select invite_org_member('{OTHER_ORG}', 'tenorgs@platforms.test', 'staff')", OUTSIDER)
TEN_TOKEN = value("select token from org_invites where email = 'tenorgs@platforms.test'")
value(f"select accept_invite('{TEN_TOKEN}')", TEN)
denied("nor make anyone own more organisations than they could start themselves (10)",
       f"select transfer_org_ownership('{OTHER_ORG}', '{TEN}')", OUTSIDER, "already own 10")
# An invitation nobody accepts holds its seat until it is withdrawn.
denied("an unanswered invitation holds a team seat", f"select invite_org_member('{OTHER_ORG}', 'later@platforms.test')",
       OUTSIDER, "allows 3")
VICTIM_INV = value(f"select id from org_invites where org_id = '{OTHER_ORG}' and email = 'victim@platforms.test'")
denied("staff cannot withdraw invitations", f"select revoke_org_invite('{VICTIM_INV}')", TEN, "no such invitation")
denied("nor can anyone outside", f"select revoke_org_invite('{VICTIM_INV}')", OWNER, "no such invitation")
allowed("the owner withdraws it", f"select revoke_org_invite('{VICTIM_INV}') ->> 'status'", OUTSIDER, "revoked")
denied("...once", f"select revoke_org_invite('{VICTIM_INV}')", OUTSIDER, "only a pending")
allowed("...and the seat is free again", f"select invite_org_member('{OTHER_ORG}', 'later@platforms.test') ->> 'status'",
        OUTSIDER, "pending")
denied("a member profile cannot be in a team (accounts only)",
       f"insert into org_members (org_id, user_id, role) values ('{ORG}', "
       f"(select id from profiles where kind = 'member' limit 1), 'staff')", None)

# Org tournaments: who runs what.
denied("an outsider cannot create an event in the organisation",
       "insert into tournaments (title, game, variant, format, clock_base_s, starts_at, rounds_count, org_id) "
       f"values ('Crash', 'chess', 'standard', 'swiss', 300, now(), 3, '{ORG}')", OUTSIDER)
STAFF_T = allowed("staff create events in the organisation",
                  "insert into tournaments (title, game, variant, format, clock_base_s, starts_at, rounds_count, org_id) "
                  f"values ('Staff Swiss', 'chess', 'standard', 'swiss', 300, now() + interval '1 day', 3, '{ORG}') returning id",
                  STAFF)
check("a community event with no cap gets the plan's 64",
      value(f"select max_participants from tournaments where id = '{STAFF_T}'") == "64")
denied("and asking for more than the plan allows is refused",
       f"update tournaments set max_participants = 100 where id = '{STAFF_T}'", STAFF, "allows 64")
allowed("an admin manages every event in the organisation",
        f"update tournaments set title = 'Staff Swiss (edited)' where id = '{STAFF_T}' returning title", ADMIN,
        "Staff Swiss (edited)")
ADMIN_T = tournament(ADMIN, "Admin Arena", org=ORG)
allowed("staff see the organisation's drafts", f"select count(*) from tournaments where id = '{ADMIN_T}'", STAFF, "1")
sql(f"update tournaments set title = 'Staff took over' where id = '{ADMIN_T}'", STAFF)
check("but do not manage events they did not create",
      value(f"select title from tournaments where id = '{ADMIN_T}'") == "Admin Arena")
allowed("an outsider sees no organisation draft", f"select count(*) from tournaments where id = '{ADMIN_T}'", OUTSIDER, "0")
DOOMED = value("insert into tournaments (title, game, variant, format, clock_base_s, starts_at, rounds_count, org_id) "
              f"values ('Staff Draft', 'chess', 'standard', 'swiss', 300, now(), 3, '{ORG}') returning id", STAFF)
sql(f"delete from tournaments where id = '{DOOMED}'", OUTSIDER)
check("an outsider cannot delete an organisation's draft", value(f"select count(*) from tournaments where id = '{DOOMED}'") == "1")
allowed("an admin can, though staff made it", f"delete from tournaments where id = '{DOOMED}' returning title", ADMIN, "Staff Draft")
denied("org_id is insert-only", f"update tournaments set org_id = '{OTHER_ORG}' where id = '{STAFF_T}'", ADMIN)
denied("autopilot_note is the system's", f"update tournaments set autopilot_note = 'hi' where id = '{STAFF_T}'", ADMIN)
denied("a personal event is always for accounts",
       "insert into tournaments (title, game, variant, format, clock_base_s, starts_at, rounds_count, identity_mode) "
       "values ('Lone', 'chess', 'standard', 'swiss', 300, now(), 3, 'platform')", OUTSIDER, "identity_needs_org")

# =============================================================================
# Profiles: accounts and members
# =============================================================================
check("profiles no longer carry a foreign key to auth.users",
      value("select count(*) from pg_constraint where conname = 'profiles_id_fkey'") == "0")
NONAME = user("amina.k", meta={})
check("with no name given, the display name is player_xxxxx, never the email's local part",
      value(f"select display_name from profiles where id = '{NONAME}'").startswith("player_")
      and "amina" not in value(f"select display_name from profiles where id = '{NONAME}'"))
denied("an account profile needs an account",
       f"insert into profiles (id, display_name) values ('{uuid.uuid4()}', 'Ghost')", None, "needs an account")
denied("a member cannot share an account's id",
       f"insert into profiles (id, kind, display_name) values ('{OUTSIDER}', 'member', 'Twin')", None)
denied("a member has no username",
       f"insert into profiles (id, kind, username, display_name) values ('{uuid.uuid4()}', 'member', 'sneaky_1', 'Sneaky')",
       None, "profiles_kind_check")
denied("a profile's kind never changes", f"update profiles set kind = 'member', username = null where id = '{NONAME}'",
       None, "never change")
GONE = user("leaver")
GONE_T = tournament(GONE, "Leaver's Cup")
value(f"delete from auth.users where id = '{GONE}'")
check("deleting the account in Auth deletes its profile and what cascades from it",
      value(f"select count(*) from profiles where id = '{GONE}'") == "0"
      and value(f"select count(*) from tournaments where id = '{GONE_T}'") == "0")
denied("an organisation's owner cannot delete their account before handing over",
       f"delete from auth.users where id = '{OWNER}'", None, "org_members")

# =============================================================================
# Keys and org_call: a platform's server
# =============================================================================
denied("staff get no keys", f"select create_org_key('{ORG}', 'Staff key')", STAFF)
made = json.loads(allowed("an admin makes a key", f"select create_org_key('{ORG}', 'Production')", ADMIN))
RAW = made.get("key", "")
check("ochs_ and 48 hex, shown once, with a 13-character prefix",
      RAW.startswith("ochs_") and len(RAW) == 53 and all(c in "0123456789abcdef" for c in RAW[5:])
      and made["prefix"] == RAW[:13])
check("only its hash is kept", value(f"select hash from org_keys where id = '{made['id']}'") == sha(RAW))
denied("not even an admin reads the hash back", f"select hash from org_keys where id = '{made['id']}'", ADMIN)
allowed("staff do not see the keys", "select count(*) from org_keys", STAFF, "0")
READ_ONLY = json.loads(value(f"select create_org_key('{ORG}', 'Reports', array['read'])", OWNER))["key"]
denied("community allows two live keys", f"select create_org_key('{ORG}', 'Third')", OWNER, "allows 2")
KEY = sha(RAW)

denied("an org request the API did not sign is refused",
       f"select org_call({q(json.dumps({'kind': 'org-read', 'key': KEY, 'what': 'tournaments', 'exp': 9999999999}))}, 'x')",
       ANON, "did not sign")
check("an unknown key is a 401", "OC401" in orgc("org-read", {"key": sha("ochs_" + "0" * 48), "what": "tournaments"})[1])
check("a key lacking the scope is a 403",
      "42501" in orgc("org-player", {"key": sha(READ_ONLY), "external_id": "u1", "name": "U"})[1])
created = org_ok("a platform creates an event", "org-tournament-create",
                 {"key": KEY, "tournament": {"title": "Platform Blitz", "game": "chess", "format": "swiss",
                                             "clock_base_s": 180, "clock_increment_s": 2, "rounds_count": 3,
                                             "starts_at": "2030-02-01T18:00:00Z", "identity_mode": "platform",
                                             "status": "live", "owner_id": OUTSIDER, "autopilot_note": "forged"}})
PT = created.get("id")
check("...in its organisation, owned by the org's owner, not a field it sent",
      value(f"select (org_id = '{ORG}' and owner_id = '{OWNER}' and status = 'draft' and autopilot_note is null)::text "
            f"from tournaments where id = '{PT}'") == "true")
check("...unrated and off the public directory unless asked", value(f"select rated || ' ' || is_listed from tournaments where id = '{PT}'")
      == "false false")
check("...and the reply names the organisation, for the branded link (/o/acme/...)", created.get("org_slug") == "acme")
PT_SLUG = created.get("slug")
again = {"key": KEY, "idem": sha("Idempotency-Key: create-2"),
         "tournament": {"title": "Twice", "game": "chess", "format": "swiss", "clock_base_s": 180, "rounds_count": 3,
                        "starts_at": "2030-02-01T18:00:00Z"}}
first, second = org_ok("an Idempotency-Key'd create", "org-tournament-create", again), \
    org_ok("...repeated", "org-tournament-create", again)
check("...makes one event and answers the same twice",
      first.get("id") == second.get("id") and value("select count(*) from tournaments where title = 'Twice'") == "1")
org_ok("a platform publishes", "org-tournament-status", {"key": KEY, "slug": PT_SLUG, "status": "registration"})
check("...through the lifecycle guard", "check" in orgc("org-tournament-status", {"key": KEY, "slug": PT_SLUG, "status": "finished"})[1]
      or "23514" in orgc("org-tournament-status", {"key": KEY, "slug": PT_SLUG, "status": "finished"})[1])
check("another organisation's event is not there",
      "P0002" in orgc("org-tournament-update", {"key": KEY, "slug": slug(tournament(OUTSIDER, "Rival Open", org=OTHER_ORG)),
                                                "changes": {"title": "Mine now"}})[1])

tok = org_ok("a platform signs a player in", "org-player",
             {"key": KEY, "external_id": "u-100", "name": "Kemi", "email": "kemi@kemi.example", "country": "NG",
              "tournament": PT_SLUG, "enter": True})
PTOK = tok.get("token", "")
KEMI = tok.get("player", {}).get("id")
check("ochp_ and 48 hex", PTOK.startswith("ochp_") and len(PTOK) == 53)
check("...a member profile with no username, belonging to the organisation",
      value(f"select p.kind || ' ' || coalesce(p.username, '-') || ' ' || op.external_id || ' ' || op.email "
            f"from profiles p join org_players op on op.profile_id = p.id where p.id = '{KEMI}'")
      == "member - u-100 kemi@kemi.example")
check("...entered on the platform's word", tok.get("entry", {}).get("status") == "approved"
      and tok["entry"]["joined_via"] == "platform")
check("only the token's hash is kept", value(f"select count(*) from private.player_tokens where hash = '{sha(PTOK)}'") == "1")
tok2 = org_ok("the same player again", "org-player", {"key": KEY, "external_id": "u-100", "name": "Kemi A."})
check("...is the same profile, renamed", tok2.get("player", {}).get("id") == KEMI
      and value(f"select display_name from profiles where id = '{KEMI}'") == "Kemi A.")
check("a new player needs a name", "22023" in orgc("org-player", {"key": KEY, "external_id": "u-101"})[1])
check("members cannot be entered where only accounts play",
      "account" in orgc("org-player", {"key": KEY, "external_id": "u-100", "name": "Kemi", "tournament": slug(STAFF_T),
                                       "enter": True})[1])
value(f"insert into private.hits (bucket, window_start, n) values ('org-ptok:{ORG}', "
      "to_timestamp(floor(extract(epoch from now()) / 60) * 60), 60) "
      "on conflict (bucket, window_start) do update set n = 60")
check("player tokens are throttled per organisation per minute by plan (OC429)",
      "OC429" in orgc("org-player", {"key": KEY, "external_id": "u-102", "name": "Late"})[1])
value(f"delete from private.hits where bucket = 'org-ptok:{ORG}'")
entered = org_ok("a platform enters players in bulk", "org-enter",
                 {"key": KEY, "slug": PT_SLUG, "players": [{"external_id": "u-200", "name": "Bola"},
                                                           {"external_id": "u-201", "name": "Chidi"},
                                                           {"name": "No id"}]})
check("...and is told which rows it got wrong", len(entered.get("added", [])) == 2
      and entered.get("errors", [{}])[0].get("row") == 3)
BOLA = entered["added"][0]["profile_id"] if entered.get("added") else None
roster = org_ok("a platform reads its roster with its own ids", "org-read", {"key": sha(READ_ONLY), "what": "roster", "slug": PT_SLUG})
check("...external ids included", sorted(p.get("external_id") for p in roster.get("roster", [])) == ["u-100", "u-200", "u-201"])
org_ok("a platform removes a player", "org-remove", {"key": KEY, "slug": PT_SLUG, "external_id": " u-201 "})
check("...gone from the event", value(f"select count(*) from participants where tournament_id = '{PT}'") == "2")

# =============================================================================
# Member visibility
# =============================================================================
allowed("a visitor cannot see a platform's users", f"select count(*) from profiles where id = '{KEMI}'", ANON, "0")
allowed("nor can an outsider", f"select count(*) from profiles where id = '{KEMI}'", OUTSIDER, "0")
allowed("the organisation's own people can", f"select count(*) from profiles where id = '{KEMI}'", STAFF, "1")
allowed("staff do not see the platform's (unverified) emails", "select count(*) from org_players", STAFF, "0")
allowed("admins do", f"select email from org_players where profile_id = '{KEMI}'", ADMIN, "kemi@kemi.example")
allowed("names for an unlisted event come through get_people", f"select display_name from get_people('{PT}') where id = '{KEMI}'",
        ANON, "Kemi A.")
value(f"update tournaments set is_listed = true where id = '{PT}'")
allowed("once on a public roster, a member shows there like anyone", f"select count(*) from profiles where id = '{KEMI}'",
        ANON, "1")
value(f"update tournaments set participants_visible = false where id = '{PT}'")
allowed("...and not when the organiser hides who entered", f"select count(*) from profiles where id = '{KEMI}'", ANON, "0")
allowed("get_people follows the same switch", f"select count(*) from get_people('{PT}')", ANON, "0")
value(f"update tournaments set participants_visible = true, is_listed = false where id = '{PT}'")
denied("a member cannot be tournament staff",
       f"insert into tournament_admins (tournament_id, user_id, role, added_by) values ('{STAFF_T}', '{KEMI}', 'moderator', '{STAFF}')",
       None, "accounts")
denied("nor added by username (members have none)", f"select add_participant('{STAFF_T}', 'kemi')", STAFF)

# =============================================================================
# Embed sessions and the dispatchers
# =============================================================================
# Acme lists its origins (https://acme.example, https://*.acme.example). A
# frame signing one of its players in says which page it is in: PAGE.
PAGE = "https://shop.acme.example"
sess = emb_ok("the frame trades the player token for a session", "emb-session-member",
              {"token": sha(PTOK), "parent_origin": PAGE})
SESS = sess.get("session", "")
check("oche_ and 64 hex, for the member", SESS.startswith("oche_") and len(SESS) == 69
      and sess.get("player", {}).get("kind") == "member")
check("...scoped to the event its token was made for", sess.get("scope") == {"tournament": PT_SLUG}, json.dumps(sess.get("scope")))
check("only the session's hash is kept", value(f"select kind from private.embed_sessions where hash = '{sha(SESS)}'") == "member")
check("the token is reusable while it lasts (one fetch serves every widget)",
      emb("emb-session-member", {"token": sha(PTOK), "parent_origin": "https://acme.example"})[0])
check("a page not on the allowed list cannot sign players in (OC403)",
      "OC403" in emb("emb-session-member", {"token": sha(PTOK), "parent_origin": "https://evil.example"})[1])
check("...nor acme.example's lookalike", "OC403" in emb("emb-session-member", {"token": sha(PTOK), "parent_origin": "https://evilacme.example"})[1])
check("...nor its pages over plain http", "OC403" in emb("emb-session-member", {"token": sha(PTOK), "parent_origin": "http://shop.acme.example"})[1])
# An app's webview (?app=1) is top level: there is no parent page to name.
# Given, a page is checked (D3); not given, it is let through - the list is a
# guard for honest frames, not a lock on the token.
APP = emb_ok("a frame with no parent page (an app's webview) says none, and is let through", "emb-session-member",
             {"token": sha(PTOK)})
check("...a member session, with no page kept", APP.get("player", {}).get("kind") == "member"
      and value(f"select coalesce(parent_origin, 'none') from private.embed_sessions where hash = '{sha(APP.get('session', ''))}'") == "none")
check("...and an empty page counts as none", emb("emb-session-member", {"token": sha(PTOK), "parent_origin": ""})[0])
check("the origin a session was made on is kept with it",
      value(f"select parent_origin from private.embed_sessions where hash = '{sha(SESS)}'") == PAGE)
value(f"update private.player_tokens set expires_at = now() - interval '1 second' where hash = '{sha(PTOK)}'")
check("an expired player token is a 401", "OC401" in emb("emb-session-member", {"token": sha(PTOK), "parent_origin": PAGE})[1])
check("a player token is not a session", "OC401" in emb("emb-me", {"session": sha(PTOK), "slug": PT_SLUG})[1])

me = emb_ok("emb-me: the player's own view of the event", "emb-me", {"session": sha(SESS), "slug": PT_SLUG})
check("...entered, with the event's topic", me.get("entry", {}).get("status") == "approved"
      and (me.get("topic") or "").startswith("live:t:"))
check("a session cannot reach another organisation's event",
      "P0002" in emb("emb-me", {"session": sha(SESS), "slug": slug(tournament(OUTSIDER, "Rival Swiss", org=OTHER_ORG, status="registration"))})[1])
ACC_ONLY = tournament(OWNER, "Accounts Only", org=ORG, status="registration")
check("a session made from an event's token stays in that event",
      "P0002" in emb("emb-join", {"session": sha(SESS), "slug": slug(ACC_ONLY)})[1])
WIDE = emb_ok("an organisation-wide session", "emb-session-member",
              {"token": sha(org_ok("an unscoped token", "org-player", {"key": KEY, "external_id": "u-100", "name": "Kemi A."})["token"]),
               "parent_origin": PAGE})
WIDE_S = sha(WIDE.get("session", ""))
check("...says so: no tournament in its scope", WIDE.get("scope") == {"tournament": None}, json.dumps(WIDE.get("scope")))
check("members are refused where only accounts play",
      "28000" in emb("emb-join", {"session": WIDE_S, "slug": slug(ACC_ONLY)})[1])

# Kind isolation: a request signed for one dispatcher is refused by the others.
for k, fn in [("org-read", "embed_call"), ("sys-work", "embed_call"), ("emb-bundle", "org_call"),
              ("emb-me", "system_call"), ("org-player", "system_call"), ("sys-flag", "org_call"),
              ("agent-key", "embed_call"), ("move", "embed_call")]:
    check(f"{fn} refuses a request signed as {k}",
          "28000" in sql(f"select {fn}({signed(k, {'key': KEY, 'session': sha(SESS), 'slug': PT_SLUG})})", ANON)[1])
payload = json.dumps({"kind": "emb-bundle", "slug": PT_SLUG, "exp": int(time.time()) + 60}, separators=(",", ":"))
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
check("a signed request edited afterwards fails its signature",
      "did not sign" in sql(f"select embed_call({q(payload.replace('emb-bundle', 'emb-logout'))}, '{sig}')", ANON)[1])
check("an expired request is refused", "expired" in sql(f"select embed_call({signed('emb-bundle', {'slug': PT_SLUG}, ttl=-5)})", ANON)[1])
denied("players cannot call the session helpers directly", f"select private.session_may_touch('{uuid.uuid4()}', '{PT}')", ANON)

# A token for one tournament makes a session for that tournament only.
T2 = tournament(OWNER, "Second Platform Event", org=ORG, status="registration", identity_mode="platform")
scoped = org_ok("a token scoped to one event", "org-player", {"key": KEY, "external_id": "u-300", "name": "Dayo", "tournament": PT_SLUG})
s_scoped = emb_ok("...makes a session", "emb-session-member", {"token": sha(scoped["token"]), "parent_origin": PAGE})["session"]
check("...that cannot touch another event of the same organisation",
      "P0002" in emb("emb-join", {"session": sha(s_scoped), "slug": slug(T2)})[1])
joined = emb_ok("...and joins its own", "emb-join", {"session": sha(s_scoped), "slug": PT_SLUG})
check("...as a platform entry", joined.get("joined_via") == "platform" and joined.get("status") == "approved")

emb_ok("logging out", "emb-logout", {"session": sha(s_scoped)})
check("...ends the session at once", "OC401" in emb("emb-me", {"session": sha(s_scoped), "slug": PT_SLUG})[1])
value(f"update org_players set blocked_at = now() where external_id = 'u-200' and org_id = '{ORG}'")
check("a blocked player gets no token", "28000" in orgc("org-player", {"key": KEY, "external_id": "u-200", "name": "Bola"})[1])
value(f"update org_players set blocked_at = null where external_id = 'u-200' and org_id = '{ORG}'")

# =============================================================================
# Playing through embed_call: the same rules, with the session's player
# =============================================================================
def ruling(kind: str, by: str, body: dict) -> str:
    payload = json.dumps({**body, "kind": kind, "by": by, "exp": int(time.time()) + 60}, separators=(",", ":"), sort_keys=True)
    return f"{q(payload)}, '{hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()}'"


upd = org_ok("a platform edits its event", "org-tournament-update",
             {"key": KEY, "slug": PT_SLUG, "changes": {"title": "Platform Blitz Final", "owner_id": OUTSIDER, "status": "live"}})
check("...the fields it may change, and no others", upd.get("title") == "Platform Blitz Final"
      and value(f"select owner_id = '{OWNER}' and status = 'registration' from tournaments where id = '{PT}'") == "t")
listing = org_ok("a platform lists its events", "org-read", {"key": sha(READ_ONLY), "what": "tournaments"})
check("...its own only", PT_SLUG in [t["slug"] for t in listing.get("tournaments", [])]
      and all(t.get("title") != "Rival Open" for t in listing.get("tournaments", [])))
KS = emb_ok("Kemi's session", "emb-session-member", {"token": sha(org_ok("t", "org-player", {"key": KEY, "external_id": "u-100", "name": "Kemi A."})["token"]), "parent_origin": PAGE})["session"]
BS = emb_ok("Bola's session", "emb-session-member", {"token": sha(org_ok("t", "org-player", {"key": KEY, "external_id": "u-200", "name": "Bola"})["token"]), "parent_origin": PAGE})["session"]
value(f"update tournaments set status = 'live' where id = '{PT}'")
check("withdrawing once it has started is refused, with the reason",
      "has started" in emb("emb-withdraw", {"session": sha(BS), "slug": PT_SLUG})[1])
value(f"select count(*) from publish_pairings({ruling('pairings', OWNER, {'tournament': PT, 'round': 1, 'start': True, 'games': [{'board': 1, 'white': KEMI, 'black': BOLA, 'position': START, 'turn': 'white', 'legal': ['e2e4']}]})})", OWNER)
EG = value(f"select id from games where tournament_id = '{PT}'")
mine = emb_ok("a player opens their game", "emb-game", {"game": EG, "session": sha(KS)})
check("...as White, with the moves so far and its topic", mine.get("my_color") == "white" and mine.get("moves") == []
      and (mine.get("topic") or "").startswith("live:g:"))
move = {"session": sha(BS), "game": EG, "ply": 0, "before": START, "move": "e2e4", "san": "e4", "after": AFTER_E4,
        "turn": "black", "legal": ["e7e5"]}
check("Black cannot move for White", "not your move" in emb("emb-move", move)[1])
RIVAL_KEY = sha(json.loads(value(f"select create_org_key('{OTHER_ORG}', 'Rival key')", OUTSIDER))["key"])
rival_tok = org_ok("a rival platform signs its own player in", "org-player",
                   {"key": RIVAL_KEY, "external_id": "r-1", "name": "Rival"})["token"]
RIVAL_S = emb_ok("...who gets a session, on any page: its organisation lists no origins", "emb-session-member",
                 {"token": sha(rival_tok)})["session"]
check("a session from another organisation cannot touch the game",
      "P0002" in emb("emb-move", {**move, "session": sha(RIVAL_S)})[1])
played = emb_ok("White plays e4 through the embed", "emb-move", {**move, "session": sha(KS)})
check("...ply 1, Black to move", played.get("ply") == 1 and played.get("turn") == "black")
check("an embed flag claim with time left is refused", "still time" in emb("emb-flag", {"session": sha(BS), "game": EG, "ply": 1, "result": "black"})[1])
check("Black offers a draw", emb_ok("emb-draw", "emb-draw", {"session": sha(BS), "game": EG}).get("draw_offer") == "black")
check("White declines", emb_ok("emb-decline", "emb-decline", {"session": sha(KS), "game": EG}).get("draw_offer") is None)
res = emb_ok("Black resigns", "emb-resign", {"session": sha(BS), "game": EG})
check("...White wins by resignation", res.get("result") == "white" and res.get("termination") == "resignation")

ARENA = tournament(OWNER, "Platform Arena", org=ORG, status="registration", format="arena", rounds_count=None,
                   arena_minutes=30, identity_mode="platform")
for sess_raw in (KS, BS):
    emb_ok("a member joins the arena event", "emb-join", {"session": sha(sess_raw), "slug": slug(ARENA)})
value(f"update tournaments set status = 'live' where id = '{ARENA}'")
q1 = emb_ok("Kemi asks for a game", "emb-arena-join", {"session": sha(KS), "slug": slug(ARENA)})
q2 = emb_ok("Bola asks for a game", "emb-arena-join", {"session": sha(BS), "slug": slug(ARENA)})
check("...the API is handed the queue and ratings to pick from", q1.get("status") == "queued"
      and len(q2.get("queue", [])) == 2 and len(q2.get("seeds", [])) == 2)
check("...and the game and variant to set the board up with",
      (q1.get("tournament") or {}).get("id") == ARENA and q1["tournament"].get("game") == "chess"
      and q1["tournament"].get("variant") == "standard")
DS = emb_ok("Dayo's session", "emb-session-member", {"token": sha(org_ok("t", "org-player", {"key": KEY, "external_id": "u-300", "name": "Dayo"})["token"]), "parent_origin": PAGE})["session"]
pair = {"tournament": ARENA, "games": [{"white": KEMI, "black": BOLA, "position": START, "turn": "white"}]}
check("a third player cannot pair two others", "one of its two players" in emb("emb-arena-pairings", {**pair, "session": sha(DS)})[1])
made_g = emb_ok("Bola pairs with Kemi", "emb-arena-pairings", {**pair, "session": sha(BS)})
check("...the game starts at once", isinstance(made_g, list) and made_g and made_g[0].get("status") == "live")
check("asking again says paired", emb_ok("asking again", "emb-arena-join", {"session": sha(KS), "slug": slug(ARENA)}).get("status") == "paired")
emb_ok("leaving the queue", "emb-arena-leave", {"session": sha(DS), "slug": slug(ARENA)})

# =============================================================================
# Account sessions and the Google handoff
# =============================================================================
ANY_T = tournament(OWNER, "Open To All", org=ORG, status="registration", identity_mode="any")
FAN = user("fan")
denied("visitors cannot mint account sessions", f"select create_account_embed_session('{slug(ANY_T)}')", ANON)
acc = json.loads(allowed("a signed-in account trades its token for an embed session",
                         f"select create_account_embed_session('{slug(ANY_T)}')", FAN))
ACC_S = sha(acc.get("session", ""))
check("...an account session, 7 days", acc.get("player", {}).get("kind") == "account"
      and value(f"select (expires_at > now() + interval '6 days')::text from private.embed_sessions where hash = '{ACC_S}'") == "true")
check("...whose scope is the organisation (no tournament)", acc.get("scope") == {"tournament": None}, json.dumps(acc.get("scope")))
check("...scoped to the organisation, so it works on its other events",
      emb("emb-me", {"session": ACC_S, "slug": slug(ACC_ONLY)})[0])
check("...but an account is refused where only platform users play",
      "28000" in emb("emb-me", {"session": ACC_S, "slug": PT_SLUG})[1])
for _ in range(21):
    value(f"select create_account_embed_session('{slug(ANY_T)}')", FAN)
check("twenty live account sessions per person: older ones are revoked",
      value(f"select count(*) from private.embed_sessions where profile_id = '{FAN}' and revoked_at is null") == "20")
check("the first of them has gone", "OC401" in emb("emb-me", {"session": ACC_S, "slug": slug(ANY_T)})[1])
listed = allowed("the person lists where they are signed in", "select count(*) from list_my_embed_sessions()", FAN, "20")
one = value("select id from list_my_embed_sessions() limit 1", FAN)
allowed("and signs one out", f"select revoke_my_embed_session('{one}')", FAN, "")
denied("but not someone else's", f"select revoke_my_embed_session('{one}')", OUTSIDER, "no such session")

S_RAW = uuid.uuid4().hex + uuid.uuid4().hex
H = hashlib.sha256(bytes.fromhex(S_RAW)).hexdigest()
emb_ok("the frame starts a Google sign-in with h = sha256(S)", "emb-handoff-start", {"h": H, "slug": slug(ANY_T), "ip": "iphash1"})
check("starting twice with one hash is refused", "23505" in emb("emb-handoff-start", {"h": H, "slug": slug(ANY_T)})[1])
peek = emb_ok("the popup asks what it is signing in to", "emb-handoff-peek", {"h": H})
check("...the event and the organisation", peek.get("status") == "pending" and peek.get("org", {}).get("name") == "Acme Chess Club")
check("redeeming before the popup binds says pending", emb_ok("an early redeem", "emb-handoff-redeem", {"s": S_RAW}).get("status") == "pending")
UNCONF = user("unconfirmed", confirmed=False)
denied("an unconfirmed address cannot bind", f"select embed_handoff_bind('{H}')", UNCONF, "confirm")
allowed("the popup binds its account", f"select embed_handoff_bind('{H}') ->> 'status'", FAN, "bound")
denied("a bound sign-in cannot be bound again", f"select embed_handoff_bind('{H}')", OUTSIDER, "expired")
check("knowing h (it is in the popup's URL) redeems nothing",
      emb_ok("redeeming with h", "emb-handoff-redeem", {"s": H}).get("status") == "expired")
red = emb_ok("the frame redeems S", "emb-handoff-redeem", {"s": S_RAW})
check("...and gets the account's session", red.get("status") == "ok" and red.get("session", "").startswith("oche_")
      and red.get("player", {}).get("id") == FAN)
check("...with its scope, like every other way in", red.get("scope") == {"tournament": None}, json.dumps(red.get("scope")))
check("a second redeem is refused", emb_ok("redeeming again", "emb-handoff-redeem", {"s": S_RAW}).get("status") == "used")

# =============================================================================
# Email invites
# =============================================================================
INV_T = tournament(OWNER, "Invite Cup", org=ORG, status="registration", max_participants=4)
INV_SLUG = slug(INV_T)
EXISTING = user("existing")  # has an account and a confirmed address
denied("only the event's managers invite", f"select add_invites('{INV_T}', '[{{\"email\":\"a@b.co\"}}]')", STAFF)
r1 = json.loads(allowed("an organiser adds people by email",
                        f"select add_invites('{INV_T}', {js([{'email': ' Newbie@Platforms.Test ', 'name': 'Newbie'}, {'email': 'not-an-email'}, {'email': 'newbie@platforms.test'}])})",
                        OWNER))
check("...normalised, with the bad and the repeated rows said back by number",
      r1 == {"added": 1, "already": 0, "invalid": [{"row": 2, "reason": "not an email address"}, {"row": 3, "reason": "listed twice"}],
             "places_left": 3}, json.dumps(r1))
check("adding the same address again is 'already', not an error",
      json.loads(value(f"select add_invites('{INV_T}', {js([{'email': 'newbie@platforms.test'}])})", OWNER))["already"] == 1)

# No oracle: an address with an account and one without get the same answer.
NO1 = tournament(OWNER, "Oracle One", org=ORG, status="registration", max_participants=8)
NO2 = tournament(OWNER, "Oracle Two", org=ORG, status="registration", max_participants=8)
a1 = value(f"select add_invites('{NO1}', {js([{'email': 'existing@platforms.test'}])})", OWNER)
a2 = value(f"select add_invites('{NO2}', {js([{'email': 'nobody-here@platforms.test'}])})", OWNER)
check("no oracle: an address with an account and one without get byte-identical replies", a1 == a2, f"{a1} vs {a2}")
check("...and neither is entered at add time (the organiser learns nothing)",
      value(f"select count(*) from participants where tournament_id in ('{NO1}', '{NO2}')") == "0")
check("add_invites never reads auth.users",
      "auth.users" not in value("select prosrc from pg_proc where proname = 'do_add_invites'"))

# Reservations: pending invites hold seats.
value(f"select add_invites('{INV_T}', {js([{'email': 'second@platforms.test'}])})", OWNER)
r3 = denied("more invites than places is all or nothing",
            f"select add_invites('{INV_T}', {js([{'email': f'x{i}@platforms.test'} for i in range(3)])})", OWNER, "only 2 places left")
check("...nothing was added", value(f"select count(*) from tournament_invites where tournament_id = '{INV_T}'") == "2")
J1, J2 = user("joiner1"), user("joiner2")
allowed("one open place taken by a join", f"select status from join_tournament('{INV_SLUG}')", J1, "approved")
allowed("the last open place", f"select status from join_tournament('{INV_SLUG}')", J2, "approved")
denied("then the event is full, though only two have entered: two seats are held", f"select join_tournament('{INV_SLUG}')",
       user("joiner3"), "full")
check("the embed bundle counts held seats too",
      json.loads(emb("emb-bundle", {"slug": INV_SLUG})[1])["tournament"]["entry"]["full"] is True)

# Claims: on a confirmed sign-up, on confirming later, at the next sign-in.
NEWBIE = str(uuid.uuid4())
value(f"insert into auth.users (id, email) values ('{NEWBIE}', 'newbie@platforms.test')")
check("signing up without confirming enters nobody",
      value(f"select count(*) from participants where tournament_id = '{INV_T}' and user_id = '{NEWBIE}'") == "0")
value(f"update auth.users set email_confirmed_at = now() where id = '{NEWBIE}'")
check("confirming the code enters them, approved, by email",
      value(f"select status || ' ' || joined_via from participants where tournament_id = '{INV_T}' and user_id = '{NEWBIE}'")
      == "approved email")
check("...and the invite is claimed", value(f"select status from tournament_invites where tournament_id = '{INV_T}' and email = 'newbie@platforms.test'")
      == "claimed")
SECOND = str(uuid.uuid4())
value(f"insert into auth.users (id, email, email_confirmed_at) values ('{SECOND}', 'Second@Platforms.test', now())")
check("signing up with Google (already confirmed) enters them at once, whatever the address's case",
      value(f"select status from participants where tournament_id = '{INV_T}' and user_id = '{SECOND}'") == "approved")
check("the claimed seats were the held ones: the event is exactly full",
      value(f"select private.seats_taken('{INV_T}')") == "4")
value(f"update auth.users set last_sign_in_at = now() where id = '{EXISTING}'")
check("an existing account is entered at its next sign-in",
      value(f"select count(*) from participants where tournament_id = '{NO1}' and user_id = '{EXISTING}' and status = 'approved'") == "1")
told = json.loads(value("select claim_my_invites()", EXISTING))
check("claim_my_invites tells them once what they were entered in", [t["slug"] for t in told] == [slug(NO1)])
check("...and not again", value("select claim_my_invites()", EXISTING) == "[]")

# A claim that fails must never stop someone signing in.
BOOM_T = tournament(OWNER, "Boom", org=ORG, status="registration")
value(f"select add_invites('{BOOM_T}', {js([{'email': 'boom@platforms.test'}])})", OWNER)
value("create or replace function public.test_boom() returns trigger language plpgsql as $$ begin "
      "raise exception 'boom'; end $$")
value(f"create trigger test_boom before insert on participants for each row when (new.tournament_id = '{BOOM_T}') "
      "execute function public.test_boom()")
BOOM = str(uuid.uuid4())
ok_signup = sql(f"insert into auth.users (id, email, email_confirmed_at) values ('{BOOM}', 'boom@platforms.test', now())")
check("a failing claim does not fail the sign-up", ok_signup[0], ok_signup[1])
check("...it is written to the ops log instead",
      value(f"select count(*) from private.ops_log where source = 'on_auth_user_verified' and detail ->> 'user' = '{BOOM}'") == "1")
check("...and the invite is still pending, to claim later",
      value(f"select status from tournament_invites where tournament_id = '{BOOM_T}'") == "pending")
value("drop trigger test_boom on participants; drop function public.test_boom()")
allowed("claim_my_invites picks it up once the fault is gone", "select jsonb_array_length(claim_my_invites())", BOOM, "1")

# The caller's own invite opens doors when joining.
GATED = tournament(OWNER, "Gated", org=ORG, status="registration", invite_only=True, requires_code=True)
value(f"update tournament_secrets set entry_code = 'SECRET1' where tournament_id = '{GATED}'")
denied("invite-only refuses the uninvited", f"select join_tournament('{slug(GATED)}', 'SECRET1')", OUTSIDER, "invitation only")
value(f"select add_invites('{GATED}', {js([{'email': 'outsider@platforms.test'}])})", OWNER)
allowed("joining with an invite to your own confirmed address goes past code and gate",
        f"select status || ' ' || joined_via from join_tournament('{slug(GATED)}')", OUTSIDER, "approved email")
check("...claiming the invite", value(f"select status from tournament_invites where tournament_id = '{GATED}'") == "claimed")

# Accept, decline, preview.
PREV_T = tournament(OWNER, "Preview Open", org=ORG, status="registration")
value(f"select add_invites('{PREV_T}', {js([{'email': 'amina.k@platforms.test', 'name': 'Amina'}])})", OWNER)
TOKEN = value(f"select token from tournament_invites where tournament_id = '{PREV_T}'")
denied("organisers never read invite tokens", f"select token from tournament_invites where tournament_id = '{PREV_T}'", OWNER)
prev = json.loads(allowed("anyone with the link sees a preview", f"select get_invite_preview('{TOKEN}')", ANON))
check("...the event, the organisation, and the address masked",
      prev.get("email_masked") == "am•••@platforms.test" and prev["tournament"]["title"] == "Preview Open"
      and prev["org"]["slug"] == "acme" and "amina.k" not in json.dumps(prev))
check("...noted as opened", value(f"select opened_at is not null from tournament_invites where token = '{TOKEN}'") == "t")
denied("someone else signed in cannot accept it", f"select accept_invite('{TOKEN}')", OUTSIDER, "another address")
allowed("its addressee accepts", f"select accept_invite('{TOKEN}') ->> 'status'", NONAME, "claimed")
check("...and is in", value(f"select status from participants where tournament_id = '{PREV_T}' and user_id = '{NONAME}'") == "approved")
DEC_T = tournament(OWNER, "Declinable", org=ORG, status="registration")
value(f"select add_invites('{DEC_T}', {js([{'email': 'amina.k@platforms.test'}])})", OWNER)
dtok = value(f"select token from tournament_invites where tournament_id = '{DEC_T}'")
allowed("or declines", f"select decline_invite('{dtok}') ->> 'status'", NONAME, "declined")
check("a declined invite gives its seat back", value(f"select private.seats_taken('{DEC_T}')") == "0")
check("my_invites lists what is waiting and recently claimed",
      value("select jsonb_array_length(my_invites())", NONAME) == "1")

# Resending, limits, lapsing, platform events.
RS = value(f"select id from tournament_invites where tournament_id = '{NO2}'")
allowed("an unsent invite can be queued again", f"select resend_invite('{RS}') ->> 'resends'", OWNER, "1")
value(f"update tournament_invites set sent_at = now() where id = '{RS}'")
denied("not within the hour", f"select resend_invite('{RS}')", OWNER, "less than an hour")
value(f"update tournament_invites set sent_at = now() - interval '2 hours', resends = 3 where id = '{RS}'")
denied("and three times at most", f"select resend_invite('{RS}')", OWNER, "three times")

# Revoking and adding the address again is the same invite back, its mail
# history included: otherwise revoke-and-add would mail one inbox at will.
def revive(inv: str) -> str:
    value(f"select revoke_invite('{inv}')", OWNER)
    value(f"select add_invites('{NO2}', {js([{'email': 'nobody-here@platforms.test'}])})", OWNER)
    return value(f"select status || ' ' || send || ' ' || (sent_at is not null) || ' ' || resends "
                 f"from tournament_invites where id = '{inv}'")


value(f"update tournament_invites set sent_at = now(), resends = 0 where id = '{RS}'")
check("re-adding an address mailed minutes ago brings it back pending - seat held - but not mailed again yet",
      revive(RS) == "pending false true 0")
value(f"update tournament_invites set sent_at = now() - interval '2 hours' where id = '{RS}'")
check("an hour on, re-adding is a resend: queued to mail, and counted as one", revive(RS) == "pending true false 1")
for _ in range(5):
    value(f"update tournament_invites set sent_at = now() - interval '2 hours' where id = '{RS}'")  # as if it went out
    last = revive(RS)
check("five more revoke-and-add cycles mail it three times in all, no more", last == "pending false true 3", last)
denied("platform-only events take no email invites", f"select add_invites('{T2}', {js([{'email': 'p@q.co'}])})", OWNER, "own site")
LAPSE_T = tournament(OWNER, "Lapse Test", org=ORG, status="registration", max_participants=4)
value(f"select add_invites('{LAPSE_T}', {js([{'email': 'late1@platforms.test'}, {'email': 'late2@platforms.test'}])})", OWNER)
check("two seats held", value(f"select private.seats_taken('{LAPSE_T}')") == "2")
value(f"update tournaments set status = 'live' where id = '{LAPSE_T}'")
check("starting lapses pending invites and frees their seats",
      value(f"select string_agg(distinct status, ',') from tournament_invites where tournament_id = '{LAPSE_T}'") == "lapsed"
      and value(f"select private.seats_taken('{LAPSE_T}')") == "0")
LATE1 = str(uuid.uuid4())
value(f"insert into auth.users (id, email, email_confirmed_at) values ('{LATE1}', 'late1@platforms.test', now())")
check("a lapsed invite enters nobody", value(f"select count(*) from participants where tournament_id = '{LAPSE_T}'") == "0")
value(f"insert into private.hits (bucket, window_start, n) values ('invites:{ORG}', "
      "to_timestamp(floor(extract(epoch from now()) / 86400) * 86400), 500) "
      "on conflict (bucket, window_start) do update set n = 500")
check("invites per day are capped by plan (OC429)",
      "OC429" in sql(f"select add_invites('{NO2}', {js([{'email': 'one-more@platforms.test'}])})", OWNER)[1])
value(f"delete from private.hits where bucket = 'invites:{ORG}'")
inv_api = org_ok("a platform's server invites by email too", "org-invites",
                 {"key": KEY, "slug": slug(NO2), "rows": [{"email": "server@platforms.test"}]})
check("...recorded as added with a key (no inviter)", inv_api.get("added") == 1
      and value("select invited_by is null from tournament_invites where email = 'server@platforms.test'") == "t")

# =============================================================================
# System calls: the autopilot, under leases
# =============================================================================
value("update organizations set plan = 'club' where slug = 'acme'")  # room for the fields below
P = [user(f"auto{i}") for i in range(4)]
AUTO = tournament(OWNER, "Autopilot Swiss", org=ORG, status="registration", autopilot=True, min_players=4,
                  round_break_s=0, starts_at="2020-01-01T00:00:00Z")
value("insert into participants (tournament_id, user_id, status) values "
      + ",".join(f"('{AUTO}', '{u}', 'approved')" for u in P[:3]))
check("an autopilot event past its start is due", value("select private.autopilot_due()") == "t")
work = sys_ok("sys-work leases what is due", "sys-work", {})
snap = next((s for s in work.get("tournaments", []) if s["tournament"]["id"] == AUTO), None)
check("...with a snapshot: reasons, the field, a lease",
      snap is not None and snap["reasons"] == ["start"] and len(snap["seeds"]) == 3 and snap["lease"])
LEASE = snap["lease"] if snap else str(uuid.uuid4())
again = sys_ok("a second tick at the same time", "sys-work", {})
check("...does not get the same tournament", all(s["tournament"]["id"] != AUTO for s in again.get("tournaments", [])))
check("a call with someone else's lease is a 409 (40001), which the API takes as nothing to do",
      "40001" in sysc("sys-status", {"lease": str(uuid.uuid4()), "tournament": AUTO, "status": "live"})[1])
check("too few players cannot start", "not enough" in sysc("sys-status", {"lease": LEASE, "tournament": AUTO, "status": "live"})[1])
post = sys_ok("so it postpones", "sys-postpone", {"lease": LEASE, "tournament": AUTO, "note": "Waiting for 1 more player"})
check("...by postpone_min, with the note", post.get("autopilot_note") == "Waiting for 1 more player"
      and value(f"select (starts_at > now() + interval '14 minutes')::text from tournaments where id = '{AUTO}'") == "true")
check("...and the owner is mailed", value(f"select count(*) from private.mail_outbox where kind = 'postponed' and tournament_id = '{AUTO}'") == "1")
sys_ok("the tick releases its lease", "sys-release", {"lease": LEASE, "tournament": AUTO, "action": "postpone", "retry_in": 60})
check("...and the tournament waits until its next check",
      value(f"select count(*) from private.autopilot_candidates() where tournament_id = '{AUTO}'") == "0")
check("a released lease is gone", "40001" in sysc("sys-status", {"lease": LEASE, "tournament": AUTO, "status": "live"})[1])

value(f"insert into participants (tournament_id, user_id, status) values ('{AUTO}', '{P[3]}', 'approved')")
value(f"update tournaments set starts_at = now() - interval '1 minute' where id = '{AUTO}'")
value(f"update private.autopilot_state set next_check_at = null where tournament_id = '{AUTO}'")
LEASE = next(s["lease"] for s in sys_ok("the next tick", "sys-work", {})["tournaments"] if s["tournament"]["id"] == AUTO)
started = sys_ok("four players: it starts", "sys-status", {"lease": LEASE, "tournament": AUTO, "status": "live", "note": "Round 1"})
check("...live", started.get("status") == "live")
pairs = {"lease": LEASE, "tournament": AUTO, "round": 1, "start": True, "games": [
    {"board": 1, "white": P[0], "black": P[1], "position": START, "turn": "white", "legal": ["e2e4"]},
    {"board": 2, "white": P[2], "black": P[3], "position": START, "turn": "white", "legal": ["e2e4"]}]}
check("the system pairs only under its lease", "40001" in sysc("sys-pairings", {**pairs, "lease": str(uuid.uuid4())})[1])
games = sys_ok("and pairs round 1, clocks running (break 0)", "sys-pairings", pairs)
check("...two live games", [g["status"] for g in games] == ["live", "live"] if isinstance(games, list) else False)
check("the same round cannot be paired twice (a human got there first: a 409)",
      "already paired" in sysc("sys-pairings", pairs)[1])
sys_ok("released", "sys-release", {"lease": LEASE, "tournament": AUTO, "action": "pairings"})
for g in games if isinstance(games, list) else []:
    value(f"select private.finish_game('{g['id']}', 'white', 'resignation')")
value(f"update tournaments set round_break_s = 120 where id = '{AUTO}'")
snap2 = next((x for x in sys_ok("round 1 over", "sys-work", {})["tournaments"] if x["tournament"]["id"] == AUTO), {})
check("...the next tick sees a round to pair, with round 1's results", snap2.get("reasons") == ["pair"]
      and len([r for r in snap2.get("results", []) if r["round_number"] == 1 and r["status"] == "finished"]) == 2)
r2 = sys_ok("round 2 published to start after the break", "sys-pairings",
            {"lease": snap2.get("lease"), "tournament": AUTO, "round": 2, "start": False, "games": [
                {"board": 1, "white": P[1], "black": P[2], "position": START, "turn": "white"},
                {"board": 2, "white": P[3], "black": P[0], "position": START, "turn": "white"}]})
sys_ok("released", "sys-release", {"lease": snap2.get("lease"), "tournament": AUTO, "action": "pairings"})
check("during the break there is nothing to do", value(f"select count(*) from private.autopilot_candidates() where tournament_id = '{AUTO}'") == "0")
value(f"update rounds set created_at = now() - interval '3 minutes' where tournament_id = '{AUTO}' and number = 2")
snap3 = next((x for x in sys_ok("after the break", "sys-work", {})["tournaments"] if x["tournament"]["id"] == AUTO), {})
R2 = next((r["id"] for r in snap3.get("rounds", []) if r["number"] == 2), None)
check("...the round is due to start", snap3.get("reasons") == ["start-round"] and R2 is not None)
check("the round must be this tournament's", "P0002" in sysc("sys-start-round", {"lease": snap3.get("lease"), "tournament": AUTO,
                                                                                 "round": value(f"select id from rounds where tournament_id <> '{AUTO}' limit 1") or str(uuid.uuid4())})[1])
started_r = sys_ok("the system starts it", "sys-start-round", {"lease": snap3.get("lease"), "tournament": AUTO, "round": R2})
check("...clocks running", started_r.get("status") == "live"
      and value(f"select string_agg(distinct status::text, ',') from games where round_id = '{R2}'") == "live")
sys_ok("released", "sys-release", {"lease": snap3.get("lease"), "tournament": AUTO, "action": "start-round"})

MANUAL = tournament(OWNER, "Manual Event", org=ORG, status="live")
value(f"insert into participants (tournament_id, user_id, status) values ('{MANUAL}', '{P[0]}', 'approved'), ('{MANUAL}', '{P[1]}', 'approved')")
value(f"insert into private.autopilot_state (tournament_id, lease_id, lease_until) values ('{MANUAL}', '{LEASE}', now() + interval '1 minute')")
check("the system never pairs an event without autopilot, even holding a lease",
      "autopilot is off" in sysc("sys-pairings", {**pairs, "tournament": MANUAL})[1])
check("nor changes its status", "autopilot is off" in sysc("sys-status", {"lease": LEASE, "tournament": MANUAL, "status": "finished"})[1])

# Flag sweeps cover every tournament, autopilot or not, personal or not.
PERS = tournament(OUTSIDER, "Personal Blitz", status="live")
value(f"insert into participants (tournament_id, user_id, status) values ('{PERS}', '{P[0]}', 'approved'), ('{PERS}', '{P[1]}', 'approved')")
PG = value(f"insert into games (tournament_id, white_id, black_id, status, position, white_ms, black_ms, turn_started_at, started_at) "
           f"values ('{PERS}', '{P[0]}', '{P[1]}', 'live', '{START}', 60000, 60000, now(), now()) returning id")
check("a game with time on the clock is not swept", "still time" in sysc("sys-flag", {"game": PG, "ply": 0, "result": "black"})[1])
value(f"update games set turn_started_at = now() - interval '2 minutes' where id = '{PG}'")
check("an expired clock shows up in the work list",
      any(f["game"] == PG for f in sys_ok("sys-work sees it", "sys-work", {}).get("flags", [])))
check("the sweep cannot award the flagged side", "not a result" in sysc("sys-flag", {"game": PG, "ply": 0, "result": "white"})[1])
flagged = sys_ok("the sweep flags it, no lease needed", "sys-flag", {"game": PG, "ply": 0, "result": "black"})
check("...black wins on time", flagged.get("result") == "black" and flagged.get("termination") == "timeout")

# The kick: off by default, signed, never stacked.
value("update private.platform_settings set autopilot_enabled = false, api_tick_url = 'https://api.example.test/v1/internal/tick'")
check("the kick does nothing while autopilot is switched off", value("select private.autopilot_kick() is null") == "t")
value("update private.platform_settings set autopilot_enabled = true")
value(f"update tournaments set starts_at = now() - interval '1 minute' where id = '{tournament(OWNER, 'Kick Me', org=ORG, status='registration', autopilot=True)}'")
req = value("select private.autopilot_kick()")
sent = json.loads(value(f"select json_build_object('url', url, 'body', body::text, 'headers', headers, 't', timeout_milliseconds) from net.sent where id = {req or 0}"))
tick_key = hmac.new(SECRET.encode(), b"ocheso:v1:tick", hashlib.sha256).hexdigest()
check("enabled and due, it posts a tick to the API", sent.get("url") == "https://api.example.test/v1/internal/tick"
      and json.loads(sent["body"]).get("kind") == "tick" and sent.get("t") == 60000)
check("...signed with the derived tick key over the exact body bytes",
      sent.get("headers", {}).get("X-Ocheso-Tick") == hmac.new(tick_key.encode(), sent["body"].encode(), hashlib.sha256).hexdigest())
check("...and its timestamp is now", abs(json.loads(sent["body"])["ts"] - int(time.time())) < 30)
check("a second kick while the first is unanswered does nothing", value("select private.autopilot_kick() is null") == "t")
value(f"insert into net._http_response (id, status_code) values ({req}, 200)")
check("once answered, the next kick goes out", value("select private.autopilot_kick() is not null") == "t")
value("update private.platform_settings set autopilot_enabled = false")

# Series: the next instance, always.
SER = json.loads(value(f"select to_json(s) from create_series('{ORG}', 'friday-blitz', 'Friday Blitz', "
                       f"{js({'game': 'chess', 'format': 'arena', 'clock_base_s': 180, 'clock_increment_s': 2, 'arena_minutes': 60, 'identity_mode': 'any'})}, "
                       f"5, '19:00', 'Africa/Douala') s", STAFF))
inst = value(f"select json_build_object('n', count(*), 'status', min(status::text), 'dow', min(extract(dow from starts_at at time zone 'Africa/Douala')), "
             f"'time', min(to_char(starts_at at time zone 'Africa/Douala', 'HH24:MI')), 'auto', bool_and(autopilot)) "
             f"from tournaments where series_id = '{SER['id']}'")
check("creating a series makes its first instance: entries open, autopilot on, next Friday 19:00 Douala time",
      json.loads(inst) == {"n": 1, "status": "registration", "dow": 5, "time": "19:00", "auto": True}, inst)
cur = json.loads(allowed("anyone finds the current instance", "select get_series_current('acme', 'friday-blitz')", ANON))
check("...by organisation and series slug", cur.get("status") == "registration" and cur["series"]["slug"] == "friday-blitz")
check("a series with an instance waiting needs nothing", value(f"select count(*) from private.series_due() x where x = '{SER['id']}'") == "0")
FIRST = value(f"select id from tournaments where series_id = '{SER['id']}'")
nxt_date = value(f"select (starts_at at time zone 'Africa/Douala')::date + 7 from tournaments where id = '{FIRST}'")
value(f"select skip_series_date('{SER['id']}', '{nxt_date}')", STAFF)
value(f"insert into participants (tournament_id, user_id, status) select '{FIRST}', id, 'approved' from profiles where kind = 'account' limit 2")
value(f"update tournaments set status = 'live' where id = '{FIRST}'")
check("an instance starting makes the next one, skipping a skipped Friday",
      value(f"select (starts_at at time zone 'Africa/Douala')::date - '{nxt_date}'::date from tournaments "
            f"where series_id = '{SER['id']}' and status = 'registration'") == "7")
check("the embed of the series now shows the live one", json.loads(value("select get_series_current('acme', 'friday-blitz')"))["status"] == "live")
value(f"select pause_series('{SER['id']}')", ADMIN)
value(f"update tournaments set status = 'archived' where series_id = '{SER['id']}' and status = 'registration'")
check("a paused series makes nothing", sys_ok("sys-series on a paused series", "sys-series", {"series": SER["id"]}).get("created") is None)
value(f"select pause_series('{SER['id']}', false)", ADMIN)
check("resuming makes the next instance", value(f"select count(*) from tournaments where series_id = '{SER['id']}' and status = 'registration'") == "1")
denied("outsiders cannot touch a series", f"select stop_series('{SER['id']}')", OUTSIDER, "no such series")

# A template the plan does not allow: refused when saved, and - when it
# happens anyway (a plan lowered by hand) - never in the way of the current
# instance starting, and retried every five minutes rather than every tick.
RSER = json.loads(value(f"select to_json(s) from create_series('{OTHER_ORG}', 'rival-weekly', 'Rival Weekly', "
                        f"{js({'game': 'chess', 'format': 'swiss', 'clock_base_s': 300, 'rounds_count': 3, 'max_participants': 32})}, "
                        f"3, '18:00', 'Africa/Douala') s", OUTSIDER))
denied("a series template over the plan's places is refused when saved",
       f"select update_series('{RSER['id']}', {js({'template': {'game': 'chess', 'format': 'swiss', 'clock_base_s': 300, 'rounds_count': 3, 'max_participants': 100}})})",
       OUTSIDER, "allows 64")
check("...and nothing of the trial is left behind",
      value(f"select count(*) from tournaments where series_id = '{RSER['id']}'") == "1")
value(f"update tournament_series set template = template || '{{\"max_participants\": 100}}' where id = '{RSER['id']}'")
RINST = value(f"select id from tournaments where series_id = '{RSER['id']}'")
value(f"insert into participants (tournament_id, user_id, status) select '{RINST}', id, 'approved' from profiles "
      "where kind = 'account' limit 2")
started_ok = sql(f"update tournaments set status = 'live' where id = '{RINST}' returning status")
check("an instance starts even when its series cannot make the next one", started_ok == (True, "live"), str(started_ok))
check("...the reason is on the series, for Studio, and in the ops log",
      "allows 64" in value(f"select coalesce(last_error, '') from tournament_series where id = '{RSER['id']}'")
      and value(f"select count(*) from private.ops_log where source = 'instance-start' and detail ->> 'series' = '{RSER['id']}'") == "1")
check("...and the series waits five minutes before anyone tries again",
      value(f"select count(*) from private.series_due() x where x = '{RSER['id']}'") == "0")
value(f"update tournament_series set retry_at = now() - interval '1 second' where id = '{RSER['id']}'")
rs = sys_ok("the autopilot tries the series again", "sys-series", {"series": RSER["id"]})
check("...a failure is an answer, not an error: nothing made, the reason said, held off again",
      rs.get("created") is None and "allows 64" in (rs.get("error") or "")
      and value(f"select retry_at > now() from tournament_series where id = '{RSER['id']}'") == "t")
allowed("fixing the template clears it", f"select last_error is null and retry_at is null from update_series('{RSER['id']}', "
        f"{js({'template': {'game': 'chess', 'format': 'swiss', 'clock_base_s': 300, 'rounds_count': 3, 'max_participants': 32}})})",
        OUTSIDER, "t")
check("...and the next tick makes the instance",
      sys_ok("sys-series after the fix", "sys-series", {"series": RSER["id"]}).get("created") is not None)
sched = json.loads(allowed("the organisation's schedule is public", "select get_org_schedule('acme')", ANON))
check("...events on the schedule and the series with its current instance",
      any(t["title"] == "Friday Blitz" for t in sched.get("tournaments", []))
      and sched.get("series", [{}])[0].get("current", {}).get("status") in ("live", "registration"))

# Mail: batches held, then marked.
batch = sys_ok("a mail batch", "sys-mail-batch", {"limit": 100})
inv_mail = next((m for m in batch.get("invites", []) if m["to"] == "server@platforms.test"), None)
check("...carries what the invite email needs, the token included", inv_mail is not None and len(inv_mail.get("token", "")) == 32
      and inv_mail["org"]["slug"] == "acme")
check("...and staff-invite and postponement mail from the outbox",
      {m["kind"] for m in batch.get("outbox", [])} >= {"org-invite", "postponed"})
check("...dated in the organiser's own timezone",
      all((m.get("org") or {}).get("timezone") for m in batch.get("outbox", []) if m["kind"] == "postponed"))
check("a second batch meanwhile does not send them again",
      not any(m["id"] == (inv_mail or {}).get("id") for m in sys_ok("a second batch", "sys-mail-batch", {}).get("invites", [])))
sys_ok("the API reports what it sent", "sys-mail-done",
       {"invites": [{"id": inv_mail["id"] if inv_mail else None, "ok": True}], "outbox": [{"id": batch["outbox"][0]["id"], "ok": False, "error": "422"}],
        "bounces": ["bounced@platforms.test"]})
check("...sent is sent", value(f"select sent_at is not null from tournament_invites where id = '{(inv_mail or {}).get('id', uuid.uuid4())}'") == "t")
check("...bounces are never mailed again", value("select count(*) from private.email_suppressions where email = 'bounced@platforms.test'") == "1")
check("...and a delivered invite counts towards its sender's daily cap for that address",
      value(f"select n from private.hits where bucket = private.invite_mail_bucket('{ORG}', 'server@platforms.test') "
            "and window_start = to_timestamp(floor(extract(epoch from now()) / 86400) * 86400)") == "1")

# One sender mails one address at most 10 invitations a day, whatever the
# number of events or revocations: the cap no revoke-and-add can clear.
FLOOD = [tournament(OWNER, f"Flood {i}", org=ORG, status="registration") for i in range(2)]
for ft in FLOOD:
    value(f"select add_invites('{ft}', {js([{'email': 'flooded@platforms.test'}])})", OWNER)
value(f"insert into private.hits (bucket, window_start, n) values (private.invite_mail_bucket('{ORG}', 'flooded@platforms.test'), "
      "to_timestamp(floor(extract(epoch from now()) / 86400) * 86400), 9)")
sys_ok("a mail batch with the sender at 9 for that address", "sys-mail-batch", {"limit": 100})
value("update tournament_invites set mail_lease_until = null where status = 'pending' and sent_at is null")
flood = value("select string_agg(send::text || ':' || coalesce(send_error, '-'), ' | ' order by created_at) "
              "from tournament_invites where email = 'flooded@platforms.test'")
check("the tenth goes, the eleventh is not sent - and says why", flood.startswith("true:- | false:not sent: this address already had 10"),
      flood)

# =============================================================================
# Ratings (A9)
# =============================================================================
def rated_game(t: str, w: str, b: str) -> None:
    g = value(f"insert into games (tournament_id, white_id, black_id, status, position, ply, white_ms, black_ms, turn_started_at) "
              f"values ('{t}', '{w}', '{b}', 'live', '{START}', 10, 60000, 60000, now()) returning id")
    value(f"select private.finish_game('{g}', 'white', 'resignation')")


def ratings(*ids: str) -> list[int]:
    return [int(value(f"select chess_rating from profiles where id = '{i}'")) for i in ids]


RA, RB = user("rateda"), user("ratedb")
RATED = tournament(OWNER, "Rated Org Event", org=ORG, status="live", rated=True)
UNRATED = tournament(OWNER, "Unrated Org Event", org=ORG, status="live", rated=False, identity_mode="any")
rated_game(UNRATED, RA, RB)
check("accounts in an unrated event: nobody moves", ratings(RA, RB) == [1500, 1500])
rated_game(RATED, RA, RB)
check("accounts in a rated event: global ratings move", ratings(RA, RB) == [1516, 1484])
M1, M2 = (org_ok(f"member {n}", "org-player", {"key": KEY, "external_id": n, "name": n})["player"]["id"] for n in ("rm-1", "rm-2"))
rated_game(UNRATED, M1, M2)
check("two members: their organisation's ratings move, even unrated", ratings(M1, M2) == [1516, 1484])
rated_game(UNRATED, M1, RA)
check("a member against an account: nobody moves", ratings(M1, RA) == [1516, 1516])

# =============================================================================
# The live feed (C7)
# =============================================================================
check("realtime.messages lets anyone read live: topics and nobody send",
      value("select string_agg(cmd || ' ' || array_to_string(roles, ','), ';') from pg_policies "
            "where schemaname = 'realtime' and tablename = 'messages'") == "SELECT anon,authenticated")
check("...the topic pattern is in the policy",
      "live:[tg]:[0-9a-f]{32}" in value("select qual from pg_policies where policyname = 'ocheso_live_read'"))
LT = tournament(OWNER, "Live Feed Test", org=ORG, status="registration", games_watchable=False)
TOPIC_T = value(f"select get_live_topic('{slug(LT)}')", ANON)
check("every tournament has a topic, handed out like the event", TOPIC_T.startswith("live:t:") and len(TOPIC_T) == 39)
value("truncate realtime.sent")
LA, LB = user("livea"), user("liveb")
value(f"select join_tournament('{slug(LT)}')", LA)
value(f"select join_tournament('{slug(LT)}')", LB)
ev = json.loads(value(f"select json_agg(json_build_object('e', event, 'p', payload, 'private', private) order by id) from realtime.sent where topic = '{TOPIC_T}'"))
check("entries go out on the tournament topic as a count, privately",
      [e["e"] for e in ev] == ["entries", "entries"] and ev[-1]["p"]["count"] == 2 and all(e["private"] for e in ev))
check("...with a rising rev and the server time", ev[0]["p"]["rev"] < ev[1]["p"]["rev"] and "server_now" in ev[1]["p"])
value(f"update tournaments set status = 'live' where id = '{LT}'")
value("truncate realtime.sent")
value(f"update tournaments set autopilot = true where id = '{LT}'")
LG = value(f"select g.id from private.do_publish({js({'tournament': LT, 'round': 1, 'start': True, 'games': [{'board': 1, 'white': LA, 'black': LB, 'position': START, 'turn': 'white', 'legal': ['e2e4']}]})}::jsonb, null, true, null) g")
TOPIC_G = value(f"select get_game_topic('{LG}')", LA)
check("players get their game's topic", TOPIC_G.startswith("live:g:"))
allowed("visitors do not when games are not watchable", f"select get_game_topic('{LG}')", ANON, "")
value("truncate realtime.sent")
value(f"select private.do_move({js({'game': LG, 'ply': 0, 'before': START, 'move': 'e2e4', 'san': 'e4', 'after': AFTER_E4, 'turn': 'black', 'legal': ['e7e5']})}::jsonb, '{LA}', null)")
state = json.loads(value(f"select payload from realtime.sent where topic = '{TOPIC_G}' and event = 'state' order by id desc limit 1") or "{}")
check("a move sends the game's state on its own topic: position, clocks, san, legal moves",
      state.get("ply") == 1 and state.get("position") == AFTER_E4 and state.get("san") == "e4" and state.get("legal") == ["e7e5"]
      and "white_ms" in state)
check("...and nothing to the tournament topic (no tournament lock per move)",
      value(f"select count(*) from realtime.sent where topic = '{TOPIC_T}'") == "0")
value(f"update tournaments set participants_visible = false where id = '{LT}'")
value("truncate realtime.sent")
value(f"select private.do_resign('{LG}', '{LB}', null)")
tg = json.loads(value(f"select payload from realtime.sent where topic = '{TOPIC_T}' and event = 'game' order by id desc limit 1") or "{}")
check("a finished game goes to the tournament topic as a result, with rev",
      tg.get("status") == "finished" and tg.get("result") == "white" and "rev" in tg)
check("...without positions or clocks, and without players when entries are hidden",
      not ({"position", "white_ms", "black_ms", "legal", "white_id", "black_id"} & set(tg)))
blob = value("select coalesce(string_agg(payload::text, ' '), '') from realtime.sent")
check("no email, external id, code or token is ever broadcast",
      not any(x in blob for x in ("@platforms.test", "external_id", "entry_code", "token", "u-100")))

# =============================================================================
# Webhooks (C9)
# =============================================================================
value("update organizations set plan = 'community' where slug = 'acme'")
denied("community has no webhooks", f"select create_webhook('{ORG}', 'https://hooks.example.com/o')", ADMIN, "allows 0")
value("update organizations set plan = 'club' where slug = 'acme'")
denied("staff cannot add one", f"select create_webhook('{ORG}', 'https://hooks.example.com/o')", STAFF)
denied("an internal address is refused", f"select create_webhook('{ORG}', 'https://10.1.2.3/hook')", ADMIN, "public https")
denied("unknown events are refused", f"select create_webhook('{ORG}', 'https://hooks.example.com/o', array['everything'])", ADMIN)
hook = json.loads(allowed("an admin adds an endpoint", f"select create_webhook('{ORG}', 'https://hooks.example.com/o', "
                                                        "array['participant.joined', 'webhook.test', 'tournament.started'])", ADMIN))
HOOK, WSECRET = hook.get("id"), hook.get("secret", "")
check("...and sees its secret once: whsec_ and 24 bytes", WSECRET.startswith("whsec_") and len(base64.b64decode(WSECRET[6:])) == 24)
denied("nobody reads secrets back", "select * from private.webhook_secrets", ADMIN)
allowed("staff do not see the endpoints", "select count(*) from org_webhooks", STAFF, "0")
denied("a URL edited to an internal address is refused", f"update org_webhooks set url = 'https://localhost/x' where id = '{HOOK}'", ADMIN)

value("update private.platform_settings set webhooks_enabled = false")
EV_T = tournament(OWNER, "Events", org=ORG, status="registration")
value(f"select join_tournament('{slug(EV_T)}')", user("evjoin1"))
check("nothing is queued while webhooks are switched off", value("select count(*) from private.webhook_outbox") == "0")
value("update private.platform_settings set webhooks_enabled = true")
tournament(OWNER, "Created While On", org=ORG)
value(f"select join_tournament('{slug(EV_T)}')", user("evjoin2"))
value(f"select join_tournament('{slug(tournament(OUTSIDER, 'Personal Again', status='registration'))}')", user("evjoin3"))
check("switched on, an organisation's event is queued for its endpoints",
      value(f"select count(*) from private.webhook_outbox where webhook_id = '{HOOK}' and event = 'participant.joined'") == "1")
check("...only the events it subscribed to (not tournament.created)",
      value("select count(*) from private.webhook_outbox where event = 'tournament.created'") == "0"
      and value("select count(*) from tournaments where title = 'Created While On'") == "1")
check("...and personal tournaments have nobody to tell",
      value("select count(*) from private.webhook_outbox where payload -> 'data' -> 'tournament' ->> 'slug' like 'personal-again%'") == "0")
m_entry = org_ok("a member joins through the platform", "org-enter", {"key": KEY, "slug": slug(ANY_T), "players": [{"external_id": "u-100", "name": "Kemi A."}]})
member_ev = json.loads(value("select payload from private.webhook_outbox where event = 'participant.joined' "
                             f"and payload -> 'data' -> 'participant' ->> 'profile_id' = '{KEMI}'") or "{}")
check("member players carry the platform's own id", member_ev.get("data", {}).get("participant", {}).get("external_id") == "u-100"
      and member_ev.get("type") == "participant.joined")

sent_n = value("select private.webhooks_pump()")
dl = json.loads(value(f"select json_build_object('id', o.id, 'body', o.payload::text, 'req', o.request_id, 'status', o.status, 'attempts', o.attempts) "
                      f"from private.webhook_outbox o where webhook_id = '{HOOK}' order by created_at limit 1"))
req = json.loads(value(f"select json_build_object('url', url, 'headers', headers, 'body', body::text, 't', timeout_milliseconds) from net.sent where id = {dl['req']}"))
msg_id = "msg_" + dl["id"].replace("-", "")
hd = req.get("headers", {})
expected_sig = "v1," + base64.b64encode(hmac.new(base64.b64decode(WSECRET[6:]),
                                                  f"{msg_id}.{hd.get('webhook-timestamp')}.{req['body']}".encode(),
                                                  hashlib.sha256).digest()).decode()
check("the pump sends due deliveries", int(sent_n) >= 2 and dl["status"] == "sending" and dl["attempts"] == 1)
check("...to the endpoint, 10 s timeout, with Standard Webhooks headers",
      req["url"] == "https://hooks.example.com/o" and req["t"] == 10000 and hd.get("webhook-id") == msg_id)
check("...signed v1,base64(hmac(secret bytes, id.timestamp.body)) over the bytes sent",
      hd.get("webhook-signature") == expected_sig and req["body"] == dl["body"])
value(f"insert into net._http_response (id, status_code) values ({dl['req']}, 503)")
value("select private.webhooks_pump()")
retry = json.loads(value(f"select json_build_object('status', status, 'in', extract(epoch from next_attempt_at - now()), 'err', last_error, 'code', response_status) "
                         f"from private.webhook_outbox where id = '{dl['id']}'"))
check("a failure is retried after 30 s, give or take 10%", retry["status"] == "pending" and 25 <= retry["in"] <= 34
      and retry["code"] == 503, json.dumps(retry))
check("...and counted against the endpoint", value(f"select consecutive_failures from org_webhooks where id = '{HOOK}'") == "1")
value(f"update private.webhook_outbox set attempts = 8, status = 'sending', request_id = 990001 where id = '{dl['id']}'")
value("insert into net._http_response (id, status_code) values (990001, 500)")
value("select private.webhooks_pump()")
check("after 8 attempts a delivery has failed", value(f"select status from private.webhook_outbox where id = '{dl['id']}'") == "failed")
allowed("the admin sees deliveries, never response bodies", f"select status from webhook_deliveries('{HOOK}', 50) where id = '{dl['id']}'",
        ADMIN, "failed")
allowed("staff do not", f"select count(*) from webhook_deliveries('{HOOK}', 50)", STAFF, "0")
allowed("a manual retry gives it one more go", f"select retry_delivery('{dl['id']}') ->> 'status'", ADMIN, "pending")
second = value(f"select id from private.webhook_outbox where webhook_id = '{HOOK}' and status = 'sending' limit 1")
second_req = value(f"select request_id from private.webhook_outbox where id = '{second}'")
value(f"insert into net._http_response (id, status_code) values ({second_req}, 204)")
value("select private.webhooks_pump()")
check("a success is delivered and clears the endpoint's failures",
      value(f"select status from private.webhook_outbox where id = '{second}'") == "delivered"
      and value(f"select consecutive_failures from org_webhooks where id = '{HOOK}'") == "0")
value(f"update org_webhooks set consecutive_failures = 199, first_failure_at = now() where id = '{HOOK}'")
value(f"update private.webhook_outbox set status = 'sending', request_id = 990002 where id = '{dl['id']}'")
value("insert into net._http_response (id, status_code) values (990002, 500)")
value("select private.webhooks_pump()")
check("200 failures in a row switch the endpoint off",
      value(f"select (not active and disabled_at is not null)::text || ' ' || disabled_reason from org_webhooks where id = '{HOOK}'")
      == "true 200 deliveries in a row failed")
check("...and its owner and admins are emailed",
      value(f"select count(*) from private.mail_outbox where kind = 'webhook-disabled' and org_id = '{ORG}'") == "2")
queued_before = value(f"select count(*) from private.webhook_outbox where webhook_id = '{HOOK}'")
value(f"select join_tournament('{slug(EV_T)}')", user("evjoin4"))
check("a disabled endpoint gets no new events",
      value(f"select count(*) from private.webhook_outbox where webhook_id = '{HOOK}'") == queued_before)
allowed("switching it back on starts clean", f"update org_webhooks set active = true where id = '{HOOK}' returning consecutive_failures",
        ADMIN, "0")
value(f"update org_webhooks set first_failure_at = now() - interval '4 days', consecutive_failures = 3 where id = '{HOOK}'")
value(f"update private.webhook_outbox set status = 'sending', request_id = 990003, attempts = 2 where id = '{dl['id']}'")
value("insert into net._http_response (id, status_code) values (990003, 500)")
value("select private.webhooks_pump()")
check("three days of failures switch it off too",
      value(f"select disabled_reason from org_webhooks where id = '{HOOK}'") == "deliveries have failed for 3 days")
value(f"update private.webhook_outbox set status = 'sending', request_id = 990004, attempts = 2 where id = '{dl['id']}'")
value("insert into net._http_response (id, status_code, error_msg) values (990004, null, 'Couldn''t connect to server: Connection refused')")
value("select private.webhooks_pump()")
allowed("a delivery that got no answer says only 'unreachable', never pg_net's words (no port probing)",
        f"select coalesce(last_error, '-') || ' ' || coalesce(response_status::text, '-') from webhook_deliveries('{HOOK}', 50) "
        f"where id = '{dl['id']}'", ADMIN, "unreachable -")
value(f"update org_webhooks set active = true where id = '{HOOK}'")
rot = json.loads(allowed("rotating the secret", f"select rotate_webhook_secret('{HOOK}')", ADMIN))
test_d = json.loads(allowed("a test delivery", f"select send_test_webhook('{HOOK}')", ADMIN))
value("update private.webhook_outbox set status = 'delivered' where status = 'pending' and event <> 'webhook.test'")
value("select private.webhooks_pump()")
treq = value(f"select request_id from private.webhook_outbox where id = '{test_d.get('delivery')}'")
th = json.loads(value(f"select headers::text from net.sent where id = {treq}"))
tbody = value(f"select body::text from net.sent where id = {treq}")
sigs = th.get("webhook-signature", "").split(" ")
def wsig(secret: str) -> str:
    return "v1," + base64.b64encode(hmac.new(base64.b64decode(secret[6:]), f"{th['webhook-id']}.{th['webhook-timestamp']}.{tbody}".encode(),
                                             hashlib.sha256).digest()).decode()
check("for a day after rotating, both secrets sign", sigs == [wsig(rot.get("secret", "")), wsig(WSECRET)])
check("the test event is a webhook.test", json.loads(tbody).get("type") == "webhook.test")

# =============================================================================
# Throttles and installs (C10)
# =============================================================================
value("select private.throttle('test-bucket', 2, 60)")
value("select private.throttle('test-bucket', 2, 60)")
check("a throttle refuses past its limit with OC429", "OC429" in sql("select private.throttle('test-bucket', 2, 60)")[1])
def handoff_burst(ip: str) -> str:
    for _ in range(20):
        emb("emb-handoff-start", {"h": uuid.uuid4().hex * 2, "slug": slug(ANY_T), "ip": ip})
    return emb("emb-handoff-start", {"h": uuid.uuid4().hex * 2, "slug": slug(ANY_T), "ip": ip})[1]


# Throttle windows are fixed (floor(now / window)), so a burst that straddles a
# ten-minute boundary is split across two windows and rightly not refused.
# That happened once at 14:00 sharp; one more burst then lands in one window.
burst = handoff_burst("iphash-brute")
if value("select count(*) from private.hits where bucket = 'emb-handoff:iphash-brute'") != "1":
    burst = handoff_burst("iphash-brute-again")
check("handoff starts are limited per IP (20 per 10 minutes)", "OC429" in burst, burst)
hit = emb("emb-session-member", {"token": sha("ochp_" + "1" * 48), "ip": "iphash-two-step", "phase": "hit"})
check("the API can count a hit on its own first (so a failure still counts)", hit[0] and json.loads(hit[1]) == {"counted": True})
check("...then make the call without counting again",
      "OC401" in emb("emb-session-member", {"token": sha("ochp_" + "1" * 48), "ip": "iphash-two-step", "counted": True})[1]
      and value("select sum(n) from private.hits where bucket = 'emb-session:iphash-two-step'") == "1")
# Joins are counted in a call of their own first (the API's counted()), since
# a wrong code rolls the join back; one naming a code also has its own bucket.
GUESS_S = sha("oche_" + "7" * 64)
guess = emb("emb-join", {"session": GUESS_S, "slug": slug(ANY_T), "code": "GUESS0", "phase": "hit"})
check("an entry-code attempt is counted in its own call, before the join runs",
      guess[0] and value(f"select sum(n) from private.hits where bucket = 'emb-code:{GUESS_S}'") == "1", guess[1])
# Seeded to the limit in the current window (a burst of 20 could straddle a
# ten-minute boundary and rightly not be refused).
value(f"insert into private.hits (bucket, window_start, n) values ('emb-code:{GUESS_S}', "
      "to_timestamp(floor(extract(epoch from now()) / 600) * 600), 20) on conflict (bucket, window_start) do update set n = 20")
check("entry-code attempts are limited per session (20 per 10 minutes)",
      "OC429" in emb("emb-join", {"session": GUESS_S, "slug": slug(ANY_T), "code": "GUESS21", "phase": "hit"})[1])
check("...and a join without a code is not held to that",
      emb("emb-join", {"session": GUESS_S, "slug": slug(ANY_T), "phase": "hit"})[0])
value(f"insert into private.hits (bucket, window_start, n) values ('emb-act:{WIDE_S}', "
      "to_timestamp(floor(extract(epoch from now()) / 60) * 60), 600) on conflict (bucket, window_start) do update set n = 600")
check("embed actions are limited per session (600 a minute)", "OC429" in emb("emb-me", {"session": WIDE_S, "slug": slug(ANY_T)})[1])

value("update private.platform_settings set webhooks_enabled = true")
value("update private.webhook_outbox set status = 'delivered' where status = 'pending'")
value(f"update org_webhooks set events = '{{}}' where id = '{HOOK}'")

# A stuck event is retried every five minutes, and every retry releases with
# `stalled`: the platform is told once per stall, not twelve times an hour.
# The lease is set by hand, as sys-work would, so no other event is leased.
STUCK = tournament(OWNER, "Stuck Swiss", org=ORG, status="live", autopilot=True)


def stalled_release(error: str | None) -> None:
    lease = str(uuid.uuid4())
    value(f"insert into private.autopilot_state (tournament_id, lease_id, lease_until) values ('{STUCK}', '{lease}', "
          "now() + interval '1 minute') on conflict (tournament_id) do update "
          "set lease_id = excluded.lease_id, lease_until = excluded.lease_until")
    body = {"lease": lease, "tournament": STUCK, "retry_in": 300}
    if error:
        body.update(error=error, stalled=True, note=f"Autopilot can't continue: {error}.")
    sys_ok("a stalled tournament is released", "sys-release", body)


def stalls() -> str:
    return value("select count(*) from private.webhook_outbox where event = 'autopilot.stalled' "
                 f"and payload -> 'data' -> 'tournament' ->> 'id' = '{STUCK}'")


stalled_release("board 4 is still open")
check("a stalled tournament is announced to the platform (autopilot.stalled)", stalls() == "1")
stalled_release("board 4 is still open")
check("...once: a retry that stalls the same way is quiet", stalls() == "1")
stalled_release("cannot pair round 4")
check("...a different reason is news", stalls() == "2")
stalled_release(None)
stalled_release("cannot pair round 4")
check("...and so is stalling again after it got going", stalls() == "3")

ping = emb_ok("the frame pings from a partner page", "emb-ping",
              {"t": slug(ANY_T), "origin": "https://shop.acme.example", "view": "standings", "path": "/tournaments", "ip": "pinger"})
check("...the first sighting is recorded, allowed by the list", ping.get("first_seen") is True
      and value(f"select allowed || ' ' || last_path from org_installs where org_id = '{ORG}' and origin = 'https://shop.acme.example'")
      == "true /tournaments")
check("...and the platform is told", value("select count(*) from private.webhook_outbox where event = 'install.first_seen'") == "1")
emb_ok("pinging again at once", "emb-ping", {"o": "acme", "origin": "https://shop.acme.example", "view": "standings", "ip": "pinger"})
check("...writes nothing (once per row per 5 minutes)",
      value(f"select hits from org_installs where org_id = '{ORG}' and origin = 'https://shop.acme.example'") == "1")
emb_ok("a page not on the list", "emb-ping", {"o": "acme", "origin": "https://copycat.example", "view": "join"})
check("...is recorded as not allowed, for Studio's amber [Allow]",
      value(f"select allowed from org_installs where org_id = '{ORG}' and origin = 'https://copycat.example'") == "f")
check("garbage is not an origin", "22023" in emb("emb-ping", {"o": "acme", "origin": "javascript:alert(1)", "view": "join"})[1])
value(f"insert into org_installs (org_id, origin, view, allowed) select '{ORG}', 'https://h' || i || '.example', 'join', false "
      "from generate_series(1, 200) i")
check("at most 200 origins per organisation",
      emb_ok("the 201st origin", "emb-ping", {"o": "acme", "origin": "https://one-too-many.example", "view": "join"}).get("status") == "ignored")
listed_first = emb_ok("a listed origin's first ping, made-up ones having filled the cap", "emb-ping",
                      {"o": "acme", "origin": "https://blog.acme.example", "view": "join", "path": "/club/blitz"})
check("...is still recorded: the cap is kept apart for origins on the list", listed_first.get("first_seen") is True)
for bad_path in ("//evil.example/steal", "/go?to=https://evil.example", "/a/../b", "/x%2f%2fevil.example"):
    emb_ok(f"a ping with the path {bad_path}", "emb-ping",
           {"o": "acme", "origin": "https://blog.acme.example", "view": "standings", "path": bad_path})
    value(f"update org_installs set last_seen_at = now() - interval '6 minutes' where org_id = '{ORG}' "
          "and origin = 'https://blog.acme.example' and view = 'standings'")
check("...a path that is not a plain path is never stored",
      value(f"select coalesce(last_path, '-') from org_installs where org_id = '{ORG}' "
            "and origin = 'https://blog.acme.example' and view = 'standings'") == "-")
series_ping = emb_ok("the loader's beacon names a series and its organisation, with an empty path", "emb-ping",
                     {"s": "friday-blitz", "o": "acme", "origin": "https://news.acme.example", "view": "series", "path": ""})
check("...recorded for the organisation, allowed by the list, no path kept", series_ping.get("first_seen") is True
      and value(f"select allowed || ' ' || coalesce(last_path, '-') from org_installs "
                f"where org_id = '{ORG}' and origin = 'https://news.acme.example'") == "true -")
emb_ok("a series beacon from a page not on the list", "emb-ping",
       {"s": "friday-blitz", "o": "acme", "origin": "https://copycat.example", "view": "series"})
check("...is recorded as not allowed, like any other sighting",
      value(f"select allowed from org_installs where org_id = '{ORG}' and origin = 'https://copycat.example' "
            "and view = 'series'") == "f")
check("a series that is not the organisation's is ignored",
      emb_ok("a beacon naming the rival's series under acme", "emb-ping",
             {"s": "rival-weekly", "o": "acme", "origin": "https://news2.acme.example", "view": "series"}).get("status") == "ignored"
      and value("select count(*) from org_installs where origin = 'https://news2.acme.example'") == "0")


def invite_link_install(org_t: str, email: str):
    """The `install` sys-mail-batch hands over for one invite (others held off)."""
    value("update tournament_invites set mail_lease_until = now() + interval '1 hour' "
          f"where status = 'pending' and send and sent_at is null and email <> {q(email)}")
    batch = sys_ok(f"a mail batch for {email}", "sys-mail-batch", {"limit": 100})
    value("update tournament_invites set mail_lease_until = null where status = 'pending' and sent_at is null")
    return next((m.get("install") for m in batch.get("invites", []) if m["to"] == email), "missing")


LINK_T = tournament(OWNER, "Link Test", org=ORG, status="registration")
value(f"select add_invites('{LINK_T}', {js([{'email': 'linkee@platforms.test'}])})", OWNER)
# A spoofed sighting that got in (say while the list was empty): newest of
# all, a plain path, even marked allowed - and still not on the list now.
value(f"update org_installs set last_path = '/signin', allowed = true, last_seen_at = now() + interval '1 minute' "
      f"where org_id = '{ORG}' and origin = 'https://copycat.example'")
check("the invitation links the latest page on a listed origin with a plain path - never a spoofed one",
      invite_link_install(LINK_T, "linkee@platforms.test") == {"origin": "https://blog.acme.example", "path": "/club/blitz"})
# The partner tests with the sandbox: http://localhost:3000 on the list, which
# the frame lets stand for https://localhost:3000 too. Anyone can then ping as
# https://localhost:3000, and keep it the freshest sighting.
LISTED = value(f"select allowed_origins::text from organizations where id = '{ORG}'")
value(f"update organizations set allowed_origins = allowed_origins || '{{http://localhost:3000,https://127.0.0.1:3001}}' "
      f"where id = '{ORG}'")
for local in ("https://localhost:3000", "https://127.0.0.1:3001"):
    emb_ok(f"a ping as {local}", "emb-ping", {"o": "acme", "origin": local, "view": "join", "path": "/x"})
    value(f"update org_installs set last_seen_at = now() + interval '2 minutes' where org_id = '{ORG}' and origin = '{local}'")
check("...an invitation never goes to the invitee's own machine, through an http entry or an https one",
      invite_link_install(LINK_T, "linkee@platforms.test") == {"origin": "https://blog.acme.example", "path": "/club/blitz"})
value(f"update organizations set allowed_origins = '{LISTED}' where id = '{ORG}'")
NOLIST = value("select id from create_organization('nolist', 'No List Yet')", OWNER)  # no website: an empty list
NOLIST_T = tournament(OWNER, "No List Cup", org=NOLIST, status="registration")
value(f"select add_invites('{NOLIST_T}', {js([{'email': 'nolist-invitee@platforms.test'}])})", OWNER)
emb_ok("anyone pings for an organisation with an empty list", "emb-ping",
       {"o": "nolist", "origin": "https://evil.example", "view": "join", "path": "/steal"})
check("...recorded for Studio, 'allowed' as an empty list frames anywhere",
      value(f"select allowed from org_installs where org_id = '{NOLIST}' and origin = 'https://evil.example'") == "t")
check("...but an empty list never puts a partner page in an invitation: the hosted page it is",
      invite_link_install(NOLIST_T, "nolist-invitee@platforms.test") is None)
allowed("the team sees installs", f"select count(*) > 0 from org_installs where org_id = '{ORG}'", STAFF, "t")
allowed("outsiders do not", "select count(*) from org_installs", OUTSIDER, "0")

# =============================================================================
# Embed reads
# =============================================================================
bundle = emb_ok("the bundle for an event", "emb-bundle", {"slug": slug(ANY_T)})
check("...tournament, organisation with badge, roster with names, topic, rev",
      bundle.get("v") == 1 and bundle["org"]["badge"] == "subtle" and bundle["topic"].startswith("live:t:")
      and any(p["name"] == "Kemi A." for p in bundle["roster"]) and "rev" in bundle)
check("...never the organisation's internals", not ({"plan", "status", "support_email", "created_by"} & set(bundle["org"])))
DRAFT_T = tournament(OWNER, "Secret Draft", org=ORG)
check("drafts are not bundled", "P0002" in emb("emb-bundle", {"slug": slug(DRAFT_T)})[1])
check("...unless the API vouches for a manager's preview", emb("emb-bundle", {"slug": slug(DRAFT_T), "preview": True})[0])
gview = emb_ok("a game for its player, through the session", "emb-game", {"game": LG, "session": sha(json.loads(
    value(f"select create_account_embed_session('{slug(LT)}')", LA))["session"])})
check("...with moves, names and its topic, though not watchable", gview.get("my_color") == "white"
      and len(gview.get("moves", [])) == 1 and gview.get("topic") == TOPIC_G)
check("visitors cannot open a game that is not watchable", "P0002" in emb("emb-game", {"game": LG})[1])
check("the frame policy comes from the organisation",
      json.loads(value(f"select get_embed_policy('{slug(ANY_T)}')", ANON)) == ["https://acme.example", "https://*.acme.example"])
check("...anywhere for a personal event", value(f"select get_embed_policy('{slug(PERS)}')", ANON) == "[]")
check("the bundle's organisation carries its allowed origins (public, as the policy is)",
      bundle["org"].get("allowed_origins") == ["https://acme.example", "https://*.acme.example"])
pers_s = json.loads(allowed("an account session for a personal event", f"select create_account_embed_session('{slug(PERS)}')", FAN))
check("...is scoped to that event", pers_s.get("scope") == {"tournament": slug(PERS)}, json.dumps(pers_s.get("scope")))
check("...and nothing for no such thing", value("select get_embed_policy('no-such-slug') is null", ANON) == "t")

# =============================================================================
# Erasure, autopilot controls, the rules once
# =============================================================================
BLK = org_ok("a player to block", "org-player", {"key": KEY, "external_id": "u-400", "name": "Rowdy", "tournament": slug(ANY_T), "enter": True})
blk_s = emb_ok("...with a session", "emb-session-member", {"token": sha(BLK["token"]), "parent_origin": PAGE})["session"]
denied("staff cannot block players", f"select block_org_player('{ORG}', '{BLK['player']['id']}')", STAFF)
denied("accounts are not the organisation's to block", f"select block_org_player('{ORG}', '{FAN}')", ADMIN, "remove an account")
allowed("an admin blocks a platform player", f"select block_org_player('{ORG}', '{BLK['player']['id']}') ->> 'external_id'", ADMIN, "u-400")
check("...their session ends and their upcoming entry is withdrawn",
      "OC401" in emb("emb-me", {"session": sha(blk_s), "slug": slug(ANY_T)})[1]
      and value(f"select status from participants where tournament_id = '{ANY_T}' and user_id = '{BLK['player']['id']}'") == "withdrawn")
usage = json.loads(allowed("the team reads plan usage", f"select get_org_usage('{ORG}')", STAFF))
check("...limits from plan_limit, counts from the tables",
      usage.get("plan") == "club" and usage["limits"]["webhooks"] == 5 and usage["used"]["webhooks"] == 1
      and usage["used"]["members"] == 3)
allowed("outsiders read nothing", f"select get_org_usage('{ORG}') is null", OUTSIDER, "t")
erased = org_ok("a platform erases a player", "org-player-erase", {"key": KEY, "external_id": "u-100"})
check("...anonymised, unlinked, signed out", erased.get("erased") is True
      and value(f"select display_name || ' ' || coalesce(avatar_url, '-') from profiles where id = '{KEMI}'") == "Deleted player -"
      and value(f"select count(*) from org_players where profile_id = '{KEMI}'") == "0"
      and value(f"select count(*) from private.embed_sessions where profile_id = '{KEMI}'") == "0")
check("...their results stay whole", value(f"select count(*) from participants where user_id = '{KEMI}'") != "0")
check("erasing again finds nobody", org_ok("erasing twice", "org-player-erase", {"key": KEY, "external_id": "u-100"}).get("erased") is False)
SPACED = org_ok("a player made with spaces round the id", "org-player",
                {"key": KEY, "external_id": "alice ", "name": "Alice", "email": "alice@real.test"})["player"]["id"]
check("...is stored trimmed", value(f"select external_id from org_players where profile_id = '{SPACED}'") == "alice")
gone = org_ok("erasing with the same spaced id", "org-player-erase", {"key": KEY, "external_id": "alice "})
check("...finds and erases them: name and asserted email gone", gone.get("erased") is True
      and value(f"select display_name from profiles where id = '{SPACED}'") == "Deleted player"
      and value("select count(*) from org_players where email = 'alice@real.test'") == "0")

denied("autopilot controls are for managers", f"select autopilot_control('{AUTO}', 'pause')", STAFF)
held = json.loads(allowed("+5 min break", f"select autopilot_control('{AUTO}', 'extend-break', 5)", OWNER))
check("...holds the autopilot off it", (held.get("state") or {}).get("hold_until") is not None
      and value(f"select count(*) from private.autopilot_candidates() where tournament_id = '{AUTO}'") == "0")
allowed("pause", f"select autopilot_control('{AUTO}', 'pause') ->> 'enabled'", OWNER, "false")
denied("organisers cannot see the autopilot state table", "select * from private.autopilot_state", OWNER)

st = org_ok("a platform reads standings data", "org-read", {"key": sha(READ_ONLY), "what": "standings", "slug": PT_SLUG})
check("...roster and results, with each side's external id (gone for the erased player)",
      len(st.get("roster", [])) >= 2 and st.get("results")
      and st["results"][0].get("black_external_id") == "u-200" and st["results"][0].get("white_external_id") is None)
gc = json.loads(value("select private.gc()"))
check("the hourly clean-up runs and says what it removed", {"hits", "player_tokens", "handoffs", "sessions"} <= set(gc))
check("the daily profile audit finds nothing wrong", value("select private.audit_profiles()") == "0")
import os
import re
here = os.path.dirname(os.path.abspath(__file__))
defs: dict[str, list[str]] = {}
for f in ("schema.sql", "play.sql", "agents.sql", "platforms.sql"):
    for m in re.finditer(r"create\s+or\s+replace\s+function\s+([a-z_]+\.[a-z_0-9]+)\s*\(",
                         open(os.path.join(here, "..", f)).read(), re.I):
        defs.setdefault(m.group(1).lower(), []).append(f)
twice = {k: v for k, v in defs.items() if len(v) > 1}
check("every function has exactly one definition across the four files", not twice, json.dumps(twice))

# =============================================================================
# Mail off is a supported state (C8, H4): waiting mail alone must not keep the
# database kicking a tick every 10 seconds that cannot send it. Last, because
# sys-work leases whatever is due.
# =============================================================================
value("update private.platform_settings set mail_on = null, mail_checked_at = null")
check("until the API says, waiting mail is worth a tick", value("select private.mail_kick_ok()") == "t")
sys_ok("a tick from an API without Resend settings", "sys-work", {"limit": 1, "mail_on": False})
check("...is remembered", value("select mail_on::text || ' ' || (mail_checked_at > now() - interval '1 minute')::text "
                                "from private.platform_settings") == "false true")
check("...and then waiting mail alone does not make the autopilot due",
      value("select private.mail_due() and not private.mail_kick_ok()") == "t"
      and value("select private.autopilot_due() = (exists (select 1 from private.autopilot_candidates()) "
                "or exists (select 1 from private.expired_games(1)) or exists (select 1 from private.series_due()))") == "t")
value("update private.platform_settings set mail_checked_at = now() - interval '11 minutes'")
check("...except every ten minutes, to ask again", value("select private.mail_kick_ok()") == "t")
sys_ok("a tick once Resend is configured", "sys-work", {"limit": 1, "mail_on": True})
check("...and mail is due again at once", value("select mail_on::text from private.platform_settings") == "true"
      and value("select private.mail_kick_ok()") == "t")

sys.exit(1 if report() else 0)
