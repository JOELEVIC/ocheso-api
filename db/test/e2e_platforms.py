#!/usr/bin/env python3
"""
Ocheso for Platforms, end to end: the real API in-process, a real PostgREST and
the four SQL files, played the way a partner, its players, an organiser and
the database itself would play them (docs/OCHESO_PLATFORMS.md G).

  * An organisation with a key runs a Swiss on autopilot (break 0): four of
    its own users arrive through player tokens and embed sessions and join;
    the ticks that start, pair, sweep a flag and finish it are made by the
    DATABASE - private.autopilot_kick() signs them into the shim's net.sent,
    exactly as it would hand them to pg_net - and replayed to the API byte for
    byte. Every game is played through /v1/embed/games/*. The table is checked
    against the results, and the webhooks against what happened, signatures
    included.
  * Email invites: a bulk add, an unconfirmed sign-up that is not entered,
    the code confirmed and entered, an existing account entered at its next
    sign-in and another on its next page load; the organiser's answer is the
    same whether an address has an account or not.
  * The Google handoff: start, bind, redeem, and a second redeem refused.
  * Isolation and refusals: a session from one organisation cannot touch
    another's events, a secret key from a browser is refused, an Ocheso token
    where a sign-in token belongs is a clear 401.

Local only, like the other e2e suites: db/test/e2e_platforms.sh sets up the
database and PostgREST.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from e2e_harness import Player, api, check, expect, report, sql  # noqa: E402

import tokens  # noqa: E402  (core/, on the path through the harness)

ORIGIN = "https://yoursite.example"
HOOK_URL = "https://hooks.yoursite.example/ocheso"
EVERY_EVENT = [
    "tournament.created", "tournament.updated", "tournament.published", "tournament.started",
    "tournament.postponed", "tournament.finished", "tournament.archived",
    "participant.joined", "participant.approved", "participant.rejected", "participant.withdrawn",
    "participant.removed", "invite.claimed", "invite.declined", "invite.lapsed",
    "round.published", "round.started", "round.finished", "game.started", "game.finished",
    "autopilot.stalled", "install.first_seen", "webhook.test",
]


def S(session: str) -> dict:
    return {"X-Ocheso-Session": session}


def confirm(p: Player) -> None:
    """GoTrue confirming the 6-digit code: what fires the invite claims."""
    sql(f"update auth.users set email_confirmed_at = now() where id = '{p.id}'")


# -----------------------------------------------------------------------------
# The database's own tick
# -----------------------------------------------------------------------------
def kick() -> int | None:
    """private.autopilot_kick(), as pg_cron runs it every 10 s: the id of the
    request it filed with pg_net (here the shim's net.sent), or None when
    nothing was due."""
    got = sql("select private.autopilot_kick()")
    return int(got) if got else None


def db_tick(name: str) -> dict:
    """One tick as production makes it: the database decides something is due,
    builds {"kind":"tick","ts":..,"nonce":..}, signs those bytes with
    private.derived_key('ocheso:v1:tick') and posts them; the API gets exactly
    that body and header. Then pg_net's side: the answer goes into
    net._http_response, which is what lets the next kick through."""
    req = kick()
    if req is None:
        check(f"{name}: the database finds work and kicks", False, "autopilot_kick() returned null")
        return {}
    body = sql(f"select body::text from net.sent where id = {req}")
    sig = sql(f"select headers ->> 'X-Ocheso-Tick' from net.sent where id = {req}")
    r = api.post("/v1/internal/tick", content=body.encode(), headers={"X-Ocheso-Tick": sig, "Content-Type": "application/json"})
    sql(f"insert into net._http_response (id, status_code, content) values ({req}, {r.status_code}, '')")
    check(f"{name}: the API takes the database's tick", r.status_code == 200, r.text[:300])
    return r.json() if r.status_code == 200 else {}


def sql_signed(body: str) -> str:
    """A tick signature computed by the database, for a body we choose."""
    lit = body.replace("'", "''")
    return sql(f"select encode(extensions.hmac('{lit}', private.derived_key('ocheso:v1:tick'), 'sha256'), 'hex')")


def games_of(tid: str, rnd: int) -> list[dict]:
    out = sql(f"select json_agg(json_build_object('id', g.id, 'white', g.white_id, 'black', g.black_id, 'status', g.status) "
              f"order by g.board) from games g join rounds r on r.id = g.round_id "
              f"where g.tournament_id = '{tid}' and r.number = {rnd}")
    return json.loads(out) if out else []


def move(session: str, gid: str, uci: str, ply: int):
    return api.post(f"/v1/embed/games/{gid}/move", headers=S(session), json={"move": uci, "ply": ply})


# =============================================================================
# The switches the founder flips after deploying (H3), and an organisation
# =============================================================================
sql("update private.platform_settings set autopilot_enabled = true, webhooks_enabled = true, "
    "api_tick_url = 'https://api.ocheso.test/v1/internal/tick'")

owner = Player("plat-owner")
confirm(owner)
org = expect("an organiser creates an organisation", owner.post("/v1/orgs", {
    "name": "Yoursite Chess", "website": "https://yoursite.example", "timezone": "Africa/Douala",
    "allowed_origins": [ORIGIN], "brand": {"colors": {"primary": "#2f55e0"}, "radius": 10}}), 201)
ORG = org["slug"]
check("...with a slug from its name, and they own it", ORG == "yoursite-chess"
      and any(o["slug"] == ORG and o["role"] == "owner" for o in expect("their organisations", owner.get("/v1/orgs"))))
# Plans are set by hand in v1 (A7); webhooks need club.
sql(f"update organizations set plan = 'club' where slug = '{ORG}'")
made_key = expect("a secret key, shown once", owner.post(f"/v1/orgs/{ORG}/keys", {"name": "Our server"}), 201)
KEY = made_key["key"]
check("...ochs_ and 48 hex, never listed again",
      tokens.ORG_KEY.fullmatch(KEY) is not None
      and all("key" not in k and "hash" not in k for k in expect("keys list", owner.get(f"/v1/orgs/{ORG}/keys"))))
K = {"Authorization": f"Bearer {KEY}"}
hook = expect("a webhook endpoint, its secret shown once", owner.post(f"/v1/orgs/{ORG}/webhooks", {
    "url": HOOK_URL, "events": EVERY_EVENT, "description": "everything"}), 201)
HOOK, WSECRET = hook["id"], hook.get("secret", "")
check("...a whsec_ secret", WSECRET.startswith("whsec_"))

# =============================================================================
# Refusals that keep tokens where they belong
# =============================================================================
r = api.get("/v1/platform/tournaments", headers={**K, "Origin": ORIGIN})
check("a secret key from a browser (an Origin header) is refused: 400 server_only",
      r.status_code == 400 and r.json().get("code") == "server_only", r.text[:200])
for name, tok in (("an org key", KEY), ("an embed session", "oche_" + "a" * 64), ("a player token", "ochp_" + "b" * 48)):
    r = api.get("/v1/me", headers={"Authorization": f"Bearer {tok}"})
    check(f"{name} sent as a sign-in token is a clear 401 (wrong_token), not a database error",
          r.status_code == 401 and r.json().get("code") == "wrong_token" and "sign-in token" in r.json().get("detail", ""),
          r.text[:200])
r = api.get("/v1/embed/t/anything/me", headers=S(KEY))
check("an org key in X-Ocheso-Session is refused for its shape", r.status_code == 401 and r.json().get("code") == "session_required")

# =============================================================================
# A Swiss on autopilot, for the partner's own users
# =============================================================================
create = {"title": "Members Swiss", "game": "chess", "variant": "standard", "format": "swiss",
          "clock_base_s": 60, "clock_increment_s": 0, "rounds_count": 3, "starts_at": "2030-01-01T10:00:00Z",
          "identity_mode": "platform", "autopilot": True, "min_players": 4, "round_break_s": 0}
t = expect("the partner's server creates a tournament", api.post(
    "/v1/platform/tournaments", headers={**K, "Idempotency-Key": "create-members-swiss"}, json=create), 201)
SLUG, TID = t["slug"], t["id"]
check("...with snippets and the branded link (/o/{org}/{slug})",
      t["hosted_url"].endswith(f"/o/{ORG}/{SLUG}") and f'data-ocheso-tournament="{SLUG}"' in t["embed"]["script"],
      json.dumps({k: t.get(k) for k in ("hosted_url", "org_slug")}))
check("...unrated and off the public directory, as an organisation's event is unless asked",
      t["rated"] is False and t["is_listed"] is False)
again = expect("the same create retried with its Idempotency-Key", api.post(
    "/v1/platform/tournaments", headers={**K, "Idempotency-Key": "create-members-swiss"}, json=create), 201)
check("...is the same tournament, made once", again["id"] == TID
      and sql("select count(*) from tournaments where title = 'Members Swiss'") == "1")
expect("it opens for entries", api.post(f"/v1/platform/tournaments/{SLUG}/publish", headers=K))
renamed = expect("and is renamed", api.patch(f"/v1/platform/tournaments/{SLUG}", headers=K, json={"title": "Members Swiss Open"}))
check("...through the platform API", renamed["title"] == "Members Swiss Open")

members: dict[str, dict] = {}
for i, name in enumerate(["Ama", "Bea", "Cid", "Dan"], 1):
    tok = expect(f"a player token for {name}", api.post("/v1/platform/player-tokens", headers=K, json={
        "external_id": f"user-{i}", "name": name, "tournament": SLUG}))
    check(f"...ochp_ for {name}, ten minutes", tokens.PLAYER_TOKEN.fullmatch(tok["token"]) is not None)
    s = expect(f"{name}'s frame trades it for a session", api.post("/v1/embed/sessions", json={
        "player_token": tok["token"], "parent_origin": ORIGIN}), 201)
    members[s["player"]["id"]] = {"name": name, "session": s["session"], "external_id": f"user-{i}"}
    check(f"...a member session for {name}, scoped to the event its token named", tokens.EMBED_SESSION.fullmatch(s["session"]) is not None
          and s["player"]["kind"] == "member" and s.get("scope") == {"tournament": SLUG}, json.dumps(s.get("scope")))
    expect(f"{name} joins", api.post(f"/v1/embed/t/{SLUG}/join", headers=S(s["session"]), json={}))
by_name = {m["name"]: (pid, m["session"]) for pid, m in members.items()}
bad = api.post("/v1/embed/sessions", json={"player_token": tok["token"], "parent_origin": "https://copycat.example"})
check("a page not on the allowed list cannot sign players in (403 origin_not_allowed)",
      bad.status_code == 403 and bad.json().get("code") == "origin_not_allowed", bad.text[:200])
bad = api.post("/v1/embed/sessions", json={"player_token": tok["token"], "parent_origin": ORIGIN.replace("https:", "http:")})
check("...nor its own page over plain http", bad.status_code == 403, bad.text[:200])
# A partner's app opens the frame top level (?app=1) and answers need-identity
# itself: no parent page, so no parent_origin, and the list does not apply.
app = api.post("/v1/embed/sessions", json={"player_token": tok["token"]})
check("an app's webview, with no parent page to name, signs the player in all the same",
      app.status_code == 201 and app.json()["player"]["kind"] == "member", app.text[:200])
dan = by_name["Dan"][1]
w = expect("Dan withdraws before the start", api.post(f"/v1/embed/t/{SLUG}/withdraw", headers=S(dan)))
check("...withdrawn", w.get("status") == "withdrawn")
expect("...and thinks better of it", api.post(f"/v1/embed/t/{SLUG}/join", headers=S(dan), json={}))

# A fifth user entered by the server and taken out again: org-enter, org-remove.
added = expect("the server enters a fifth user directly", api.post(f"/v1/platform/tournaments/{SLUG}/players", headers=K,
                                                                    json={"players": [{"external_id": "user-5", "name": "Eve"}]}))
check("...entered at once", added["added"] == 1 and added["entered"][0]["status"] == "approved")
expect("...and withdraws her", api.delete(f"/v1/platform/tournaments/{SLUG}/players/user-5", headers=K), 204)
roster = expect("the roster, with the partner's own ids", api.get(f"/v1/platform/tournaments/{SLUG}/roster", headers=K))
check("...four, by external_id", sorted(r["external_id"] for r in roster) == ["user-1", "user-2", "user-3", "user-4"],
      json.dumps(roster)[:300])
me = expect("Ama's frame asks where she stands", api.get(f"/v1/embed/t/{SLUG}/me", headers=S(by_name["Ama"][1])))
check("...in, and round 1 is next", (me.get("entry") or {}).get("status") == "approved"
      and (me.get("next") or {}).get("round") == 1, json.dumps(me)[:300])
bundle = expect("the public bundle", api.get(f"/v1/embed/t/{SLUG}"))
check("...four entries, a topic, the branded link", bundle["tournament"]["entry"]["count"] == 4
      and bundle["realtime"]["topic"].startswith("live:t:") and bundle["hosted_url"].endswith(f"/o/{ORG}/{SLUG}"))
check("...and the organisation's allowed origins, for the frame's own check", bundle["org"].get("allowed_origins") == [ORIGIN],
      json.dumps(bundle["org"]))
pol = expect("the frame policy", api.get(f"/v1/embed/policy?t={SLUG}"))
check("...is the organisation's allowed list", pol["frame_ancestors"] == f"'self' {ORIGIN}", json.dumps(pol))

# -----------------------------------------------------------------------------
# The tick: signed by the database, checked by the API
# -----------------------------------------------------------------------------
check("the derived tick key is the same in Python and in Postgres",
      sql("select private.derived_key('ocheso:v1:tick')") == tokens.derived_key(tokens.TICK_LABEL))
check("nothing is due before the start time", kick() is None)
sql(f"update tournaments set starts_at = now() - interval '1 minute' where id = '{TID}'")
req = kick()
check("past the start time the database kicks", req is not None)
if req is not None:
    raw = sql(f"select body::text from net.sent where id = {req}")
    sent = json.loads(sql(f"select json_build_object('url', url, 'headers', headers, 't', timeout_milliseconds) "
                          f"from net.sent where id = {req}"))
    check("...to the configured URL, 60 s timeout", sent["url"] == "https://api.ocheso.test/v1/internal/tick"
          and sent["t"] == 60000)
    check("...a tick body signed over its exact bytes with derived_key('ocheso:v1:tick')",
          json.loads(raw)["kind"] == "tick" and sent["headers"]["X-Ocheso-Tick"] == sql_signed(raw)
          == tokens.tick_signature(raw.encode()))
    check("a second kick while the first is unanswered does not stack", kick() is None)
    forged = raw.replace('"tick"', '"tick" ', 1)
    r = api.post("/v1/internal/tick", content=forged.encode(),
                 headers={"X-Ocheso-Tick": sent["headers"]["X-Ocheso-Tick"], "Content-Type": "application/json"})
    check("a tick whose bytes changed is refused", r.status_code == 401 and r.json().get("code") == "bad_tick")
    stale = json.dumps({"kind": "tick", "ts": int(time.time()) - 300, "nonce": "old"})
    r = api.post("/v1/internal/tick", content=stale.encode(), headers={"X-Ocheso-Tick": sql_signed(stale)})
    check("a properly signed tick five minutes old is refused (replay)", r.status_code == 401)
    r = api.post("/v1/internal/tick", content=raw.encode(), headers={"Content-Type": "application/json"})
    check("an unsigned tick is refused", r.status_code == 401)
    r = api.post("/v1/internal/tick", content=raw.encode(),
                 headers={"X-Ocheso-Tick": sent["headers"]["X-Ocheso-Tick"], "Content-Type": "application/json"})
    sql(f"insert into net._http_response (id, status_code, content) values ({req}, {r.status_code}, '')")
    out = r.json() if r.status_code == 200 else {}
    check("the database's tick is taken", r.status_code == 200, r.text[:300])
    done = next((x for x in out.get("tournaments", []) if x["id"] == TID), {})
    check("...it went live and paired round 1", done.get("done") == ["golive", "pair:1"], json.dumps(out)[:400])
check("live", sql(f"select status from tournaments where id = '{TID}'") == "live")
r1 = games_of(TID, 1)
check("round 1: two boards, clocks running (break 0)", [g["status"] for g in r1] == ["live", "live"], json.dumps(r1))
sess = {pid: m["session"] for pid, m in members.items()}

# -----------------------------------------------------------------------------
# Round 1: a mate through the embed, and a flag swept by the database
# -----------------------------------------------------------------------------
gA, gB = r1
wa, ba = sess[gA["white"]], sess[gA["black"]]
me = expect("White's frame finds her game", api.get(f"/v1/embed/t/{SLUG}/me", headers=S(wa)))
check("...with her colour and the game's broadcast topic",
      (me.get("current_game") or {}).get("id") == gA["id"] and me["current_game"]["color"] == "white"
      and me["current_game"]["topic"].startswith("live:g:"), json.dumps(me)[:300])
view = expect("her game, through the session", api.get(f"/v1/embed/games/{gA['id']}", headers=S(wa)))
check("...position, clocks, her colour, a realtime subscription", view["my_color"] == "white"
      and view["realtime"]["topic"].startswith("live:g:") and view["game"]["ply"] == 0)
r = move(ba, gA["id"], "e7e5", 0)
check("Black cannot move first: not your move", r.status_code == 409, r.text[:200])
r = move(sess[gB["white"]], gA["id"], "e2e4", 0)
check("someone from the other board cannot move here", r.status_code == 403, r.text[:200])
r = move(wa, gA["id"], "e2e5", 0)
check("an illegal move is a 422", r.status_code == 422, r.text[:200])
last = None
for ply, (side, uci) in enumerate([(wa, "f2f3"), (ba, "e7e5"), (wa, "g2g4"), (ba, "d8h4")]):
    last = move(side, gA["id"], uci, ply)
    if last.status_code != 200:
        check(f"move {uci}", False, last.text[:300])
        break
check("Fool's mate through /v1/embed/games/*: Black mates", last is not None and last.status_code == 200
      and last.json().get("result") == "black" and last.json().get("termination") == "checkmate", last.text[:300] if last else "")
watched = expect("anyone can watch it (the organiser lets them)", api.get(f"/v1/embed/g/{gA['id']}"))
check("...four moves and the names", len(watched["moves"]) == 4 and watched["white"]["name"] in ("Ama", "Bea", "Cid", "Dan"))

sql(f"update games set turn_started_at = now() - interval '10 minutes' where id = '{gB['id']}'")
out = db_tick("the flag sweep")
check("...flags the expired clock on board 2", out.get("flags", {}).get("flagged") == 1, json.dumps(out)[:300])
check("...Black wins on time", sql(f"select result || ':' || termination from games where id = '{gB['id']}'") == "black:timeout")
out = db_tick("round 1 over")
check("...round 2 is paired at once (break 0)", any("pair:2" in x["done"] for x in out.get("tournaments", [])), json.dumps(out)[:300])

# -----------------------------------------------------------------------------
# Round 2: a draw offered, declined, offered again and agreed; a resignation
# -----------------------------------------------------------------------------
gA, gB = games_of(TID, 2)
check("round 2: two live boards", [gA["status"], gB["status"]] == ["live", "live"])
wa, ba = sess[gA["white"]], sess[gA["black"]]
offer = expect("White offers a draw", api.post(f"/v1/embed/games/{gA['id']}/draw", headers=S(wa)))
check("...offered", offer.get("draw_offer") == "white", json.dumps(offer)[:200])
declined = expect("Black declines", api.post(f"/v1/embed/games/{gA['id']}/draw/decline", headers=S(ba)))
check("...declined", declined.get("draw_offer") is None)
expect("Black offers one back", api.post(f"/v1/embed/games/{gA['id']}/draw", headers=S(ba)))
agreed = expect("White accepts", api.post(f"/v1/embed/games/{gA['id']}/draw", headers=S(wa)))
check("...a draw by agreement", agreed.get("result") == "draw" and agreed.get("status") == "finished", json.dumps(agreed)[:200])
res = expect("on board 2, Black resigns", api.post(f"/v1/embed/games/{gB['id']}/resign", headers=S(sess[gB["black"]])))
check("...White wins", res.get("result") == "white" and res.get("termination") == "resignation")
out = db_tick("round 2 over")
check("...round 3 is paired", any("pair:3" in x["done"] for x in out.get("tournaments", [])), json.dumps(out)[:300])

# -----------------------------------------------------------------------------
# Round 3: a flag claimed by the player, a resignation; then it finishes
# -----------------------------------------------------------------------------
gA, gB = games_of(TID, 3)
r = api.post(f"/v1/embed/games/{gA['id']}/flag", headers=S(sess[gA["black"]]))
check("a flag claimed with time on the clock is refused", r.status_code in (409, 400), r.text[:200])
sql(f"update games set turn_started_at = now() - interval '10 minutes' where id = '{gA['id']}'")
flagged = expect("Black claims White's flag from the frame", api.post(f"/v1/embed/games/{gA['id']}/flag", headers=S(sess[gA["black"]])))
check("...Black wins on time", flagged.get("result") == "black" and flagged.get("termination") == "timeout")
expect("on board 2, White resigns", api.post(f"/v1/embed/games/{gB['id']}/resign", headers=S(sess[gB["white"]])))
out = db_tick("round 3 over")
check("...and it finishes: every round has been played", sql(f"select status from tournaments where id = '{TID}'") == "finished",
      json.dumps(out)[:300])
check("with nothing left to do, the database stops kicking", kick() is None)

# -----------------------------------------------------------------------------
# The table, three ways: from the results, from the partner's API, in the bundle
# -----------------------------------------------------------------------------
expected = json.loads(sql(
    "select json_object_agg(p, pts) from (select p, sum(pts) as pts from ("
    f"  select white_id as p, case result when 'white' then 1 when 'draw' then 0.5 else 0 end as pts from games where tournament_id = '{TID}'"
    f"  union all select black_id, case result when 'black' then 1 when 'draw' then 0.5 else 0 end from games where tournament_id = '{TID}'"
    ") x group by p) y"))
stand = expect("the partner reads the standings", api.get(f"/v1/platform/tournaments/{SLUG}/standings", headers=K))
got = {line["player"]["id"]: line["points"] for line in stand["lines"]}
check("...each player's points are their results", got == {k: float(v) for k, v in expected.items()},
      f"{got} vs {expected}")
check("...six points shared out over three rounds of two boards", sum(got.values()) == 6.0)
check("...ranked by points", [line["points"] for line in stand["lines"]] == sorted(got.values(), reverse=True)
      and stand["lines"][0]["rank"] == 1)
check("...each line carries the partner's own id", sorted(line["player"].get("external_id") for line in stand["lines"])
      == ["user-1", "user-2", "user-3", "user-4"])
rounds = expect("and the rounds", api.get(f"/v1/platform/tournaments/{SLUG}/rounds", headers=K))
check("...three, all finished", [x["number"] for x in rounds] == [1, 2, 3] and all(x["status"] == "finished" for x in rounds),
      json.dumps([(x["number"], x["status"]) for x in rounds]))
bundle = expect("the bundle after the finish", api.get(f"/v1/embed/t/{SLUG}"))
check("...finished, with the same table", bundle["tournament"]["status"] == "finished"
      and {line["player"]["id"]: line["points"] for line in bundle["standings"]["lines"]} == got)
check("...the current and previous round with their games (a Swiss; a knockout keeps every round)",
      [(x["number"], x["status"], len(x["games"])) for x in bundle["rounds"]] == [(2, "finished", 2), (3, "finished", 2)]
      and all(g["white"] and g["black"] and g["result"] for x in bundle["rounds"] for g in x["games"]),
      json.dumps([(x["number"], x["status"], len(x["games"])) for x in bundle["rounds"]]))
check("...lean: no move lists, and a player is a name and an id", "moves" not in json.dumps(bundle["rounds"])
      and all(set(g["white"]) == {"id", "display_name", "username"} for x in bundle["rounds"] for g in x["games"]))
grouped = expect("Studio's tournaments, grouped", owner.get(f"/v1/orgs/{ORG}/tournaments"))
check("...it is under finished", any(x["slug"] == SLUG for x in grouped["finished"]))

# -----------------------------------------------------------------------------
# Webhooks: what happened, queued for the endpoint and signed as documented
# -----------------------------------------------------------------------------
events = set(sql(f"select string_agg(distinct event, ',') from private.webhook_outbox where webhook_id = '{HOOK}'").split(","))
want = {"tournament.created", "tournament.updated", "tournament.published", "participant.joined", "participant.withdrawn",
        "participant.removed", "tournament.started", "round.published", "round.started", "game.started", "game.finished",
        "round.finished", "tournament.finished"}
check("every step was queued for the organisation's endpoint", want <= events, f"missing {sorted(want - events)}")
joined = json.loads(sql(f"select payload::text from private.webhook_outbox where webhook_id = '{HOOK}' "
                        "and event = 'participant.joined' order by created_at limit 1"))
check("...members carry the partner's own id", (joined["data"]["participant"].get("external_id") or "").startswith("user-"))
check("...and nothing personal rides along",
      "token" not in sql(f"select string_agg(payload::text, '') from private.webhook_outbox where webhook_id = '{HOOK}'"))
n = int(sql("select private.webhooks_pump()") or 0)
check("the pump sends them", n >= 10, str(n))
one = json.loads(sql(f"select json_build_object('headers', headers, 'body', body::text, 'url', url) from net.sent "
                     f"where url = '{HOOK_URL}' order by id limit 1"))
hd = one["headers"]
check("...to the endpoint, with the signature the docs' snippets verify (tokens.webhook_signature)",
      one["url"] == HOOK_URL and hd.get("webhook-signature", "").split(" ")[0]
      == tokens.webhook_signature(WSECRET, hd.get("webhook-id", ""), int(hd.get("webhook-timestamp") or 0), one["body"]))
first = sql(f"select id from private.webhook_outbox where webhook_id = '{HOOK}' and status = 'sending' order by created_at limit 1")
sql(f"insert into net._http_response (id, status_code) select request_id, 500 from private.webhook_outbox where id = '{first}'")
sql("select private.webhooks_pump()")
dl = expect("Studio lists the deliveries", owner.get(f"/v1/orgs/{ORG}/webhooks/{HOOK}/deliveries?limit=100"))
failed = next((d for d in dl if d["id"] == first), {})
check("...the one that got a 500 waits to be retried", failed.get("status") == "pending" and failed.get("response_status") == 500,
      json.dumps(failed)[:200])
retried = expect("the organiser retries it now", owner.post(f"/v1/orgs/{ORG}/deliveries/{first}/retry"))
check("...due again", retried.get("id") == first and retried.get("status") == "pending")

# =============================================================================
# Email invites: entered when they sign in with that address, never before
# =============================================================================
ewa, femi = Player("ewa"), Player("femi")
confirm(ewa)
confirm(femi)
cup = expect("an accounts tournament for the organisation", owner.post("/v1/tournaments", {
    "org": ORG, "title": "Invite Cup", "game": "chess", "variant": "standard", "format": "swiss",
    "clock_base_s": 300, "rounds_count": 3, "starts_at": "2030-02-01T10:00:00Z"}), 201)
CUP = cup["slug"]
expect("open for entries", owner.post(f"/v1/tournaments/{CUP}/publish"))
added = expect("three people added by email", owner.post(f"/v1/tournaments/{CUP}/invites", {
    "rows": [{"email": "kofi@e2e.test", "name": "Kofi"}, {"email": "ewa@e2e.test"}, {"email": "femi@e2e.test", "name": "Femi"}],
    "send": True, "note": "See you on Saturday"}))
check("...three invited", added["added"] == 3 and added["already"] == 0 and added["invalid"] == [], json.dumps(added))
check("...nobody is entered at add time, accounts or not",
      sql(f"select count(*) from participants p join tournaments t on t.id = p.tournament_id where t.slug = '{CUP}'") == "0")
listed = expect("the organiser's invite list", owner.get(f"/v1/tournaments/{CUP}/invites"))
check("...three pending, never a token", len(listed) == 3 and all(i["status"] == "pending" and "token" not in i for i in listed))

# The organiser learns nothing about who has an account.
gus = Player("gus")
confirm(gus)
twins = []
for title, email in (("Twin A", "gus@e2e.test"), ("Twin B", "nobody-here@e2e.test")):
    tw = expect(f"{title}", owner.post("/v1/tournaments", {"org": ORG, "title": title, "game": "chess", "variant": "standard",
                                                           "format": "swiss", "clock_base_s": 300, "rounds_count": 3,
                                                           "starts_at": "2030-02-01T10:00:00Z"}), 201)
    twins.append(owner.post(f"/v1/tournaments/{tw['slug']}/invites", {"rows": [{"email": email}]}))
check("the answer is the same, to the byte, for an address with an account and one without",
      twins[0].status_code == twins[1].status_code == 200 and twins[0].content == twins[1].content,
      f"{twins[0].text} vs {twins[1].text}")


def entered(p: Player) -> str:
    return sql(f"select coalesce(max(p.status::text || '/' || p.joined_via::text), 'out') from participants p "
               f"join tournaments t on t.id = p.tournament_id where t.slug = '{CUP}' and p.user_id = '{p.id}'")


kofi = Player("kofi")
check("a sign-up whose code is not confirmed yet is not entered", entered(kofi) == "out")
me = expect("...not even when the site loads /v1/me", kofi.get("/v1/me"))
check("...nothing claimed", me["claimed"] == [] and entered(kofi) == "out")
confirm(kofi)
check("confirming the code enters them (the sign-in trigger)", entered(kofi) == "approved/email")
me = expect("their next page load", kofi.get("/v1/me"))
check("...tells them once: 'Yoursite entered you in Invite Cup'",
      [c["slug"] for c in me["claimed"]] == [CUP] and me["claimed"][0]["org"]["slug"] == ORG, json.dumps(me["claimed"]))
check("...and only once", expect("the page after", kofi.get("/v1/me"))["claimed"] == [])

check("an existing account is not entered until it signs in again", entered(ewa) == "out")
sql(f"update auth.users set last_sign_in_at = now() where id = '{ewa.id}'")
check("...then it is (the sign-in trigger)", entered(ewa) == "approved/email")
check("another existing account, before anything happens", entered(femi) == "out")
me = expect("...loads a page while signed in", femi.get("/v1/me"))
check("...and claim_my_invites enters them", entered(femi) == "approved/email" and [c["slug"] for c in me["claimed"]] == [CUP])
listed = expect("the organiser's list again", owner.get(f"/v1/tournaments/{CUP}/invites"))
check("...all three claimed", sorted(i["status"] for i in listed) == ["claimed"] * 3)
mine = expect("Kofi's invitations banner", kofi.get("/v1/me/invites"))
check("...shows the claim", len(mine) == 1 and mine[0]["status"] == "claimed")

# The link in the email: preview, accept, decline, revoke, resend.
hana, ivan = Player("hana"), Player("ivan")
confirm(hana)
confirm(ivan)
expect("two more invited", owner.post(f"/v1/tournaments/{CUP}/invites", {"rows": [
    {"email": "hana@e2e.test"}, {"email": "ivan@e2e.test"}, {"email": "jo@e2e.test"}, {"email": "kim@e2e.test"}]}))
tok = {e: sql(f"select token from tournament_invites where email = '{e}@e2e.test'") for e in ("hana", "ivan", "jo", "kim")}
pv = expect("the invite page, before anyone signs in", api.get(f"/v1/invites/by-token/{tok['hana']}"))
check("...shows the event and a masked address", pv["email_masked"] == "ha•••@e2e.test" and pv["tournament"]["slug"] == CUP)
r = ivan.post(f"/v1/invites/by-token/{tok['hana']}/accept")
check("someone else cannot accept it", r.status_code == 403, r.text[:200])
acc = expect("Hana accepts from the email", hana.post(f"/v1/invites/by-token/{tok['hana']}/accept"))
check("...she's in", acc["status"] == "claimed" and entered(hana) == "approved/email")
dec = expect("Ivan declines", ivan.post(f"/v1/invites/by-token/{tok['ivan']}/decline"))
check("...declined, and not entered", dec["status"] == "declined" and entered(ivan) == "out")
jo = sql("select id from tournament_invites where email = 'jo@e2e.test'")
expect("the organiser revokes Jo's invite", owner.delete(f"/v1/invites/{jo}"), 204)
check("...revoked", sql(f"select status from tournament_invites where id = '{jo}'") == "revoked")
kim = sql("select id from tournament_invites where email = 'kim@e2e.test'")
rs = expect("and sends Kim's again", owner.post(f"/v1/invites/{kim}/resend"))
check("...queued again, once", rs.get("resends") == 1 and "token" not in rs)

# =============================================================================
# The Google handoff (E4): the frame keeps S, the popup binds sha256(S)
# =============================================================================
S_HEX = os.urandom(32).hex()
H = hashlib.sha256(bytes.fromhex(S_HEX)).hexdigest()
expect("the frame starts a handoff", api.post("/v1/embed/handoff/start", json={"h": H, "slug": CUP}), 201)
pk = expect("the popup asks what it is confirming", api.get(f"/v1/embed/handoff/{H}"))
check("...the event and its organiser", pk["tournament"]["slug"] == CUP and pk["org"]["name"] == "Yoursite Chess"
      and pk["status"] == "pending")
check("the frame polls before the popup binds: pending",
      expect("redeem, early", api.post("/v1/embed/handoff/redeem", json={"s": S_HEX}))["status"] == "pending")
newbie = Player("newbie")
r = newbie.post("/v1/embed/handoff/bind", {"h": H})
check("an account whose address is not confirmed cannot bind", r.status_code == 403, r.text[:200])
bound = expect("Kofi, signed in with Google in the popup, binds", kofi.post("/v1/embed/handoff/bind", {"h": H}))
check("...bound", bound["status"] == "bound")
r = femi.post("/v1/embed/handoff/bind", {"h": H})
check("nobody else can bind it after", r.status_code == 404, r.text[:200])
red = expect("the frame redeems S", api.post("/v1/embed/handoff/redeem", json={"s": S_HEX}))
KS = red.get("session", "")
check("...an account session, for the organisation's events", red["status"] == "ok" and tokens.EMBED_SESSION.fullmatch(KS) is not None
      and red["player"]["kind"] == "account" and red.get("scope") == {"tournament": None}, json.dumps(red.get("scope")))
check("a second redeem is refused: used",
      expect("redeem again", api.post("/v1/embed/handoff/redeem", json={"s": S_HEX}))["status"] == "used")
check("a redeem with the hash instead of S finds nothing",
      expect("redeem with h", api.post("/v1/embed/handoff/redeem", json={"s": H}))["status"] == "expired")
km = expect("Kofi's frame, with that session", api.get(f"/v1/embed/t/{CUP}/me", headers=S(KS)))
check("...sees him in", (km.get("entry") or {}).get("status") == "approved")
acct = expect("an account session minted from a sign-in token", femi.post("/v1/embed/sessions/account", {"slug": CUP}), 201)
FS = acct["session"]
check("...with the same scope", acct.get("scope") == {"tournament": None}, json.dumps(acct.get("scope")))
listed = expect("Kofi's signed-in embeds", kofi.get("/v1/me/embed-sessions"))
check("...one", len(listed) == 1)
expect("he signs it out from his account", kofi.delete(f"/v1/me/embed-sessions/{listed[0]['id']}"), 204)
r = api.get(f"/v1/embed/t/{CUP}/me", headers=S(KS))
check("...and the frame is asked to sign in again (401 session_expired)",
      r.status_code == 401 and r.json().get("code") == "session_expired", r.text[:200])

# =============================================================================
# Isolation: one organisation's sessions and keys never reach another's events
# =============================================================================
rival = Player("rival-owner")
confirm(rival)
org_b = expect("a second organisation", rival.post("/v1/orgs", {"name": "Rival Club"}), 201)["slug"]
KB = {"Authorization": f"Bearer {expect('its key', rival.post(f'/v1/orgs/{org_b}/keys', {'name': 'srv'}), 201)['key']}"}
tb = expect("its arena, open to its users and accounts", api.post("/v1/platform/tournaments", headers=KB, json={
    "title": "Rival Arena", "game": "chess", "variant": "standard", "format": "arena", "clock_base_s": 60,
    "arena_minutes": 30, "starts_at": "2030-01-01T10:00:00Z", "identity_mode": "any"}), 201)
SB = tb["slug"]
expect("published", api.post(f"/v1/platform/tournaments/{SB}/publish", headers=KB))
loose = expect("an unscoped token for one of the first organisation's users", api.post(
    "/v1/platform/player-tokens", headers=K, json={"external_id": "user-1", "name": "Ama"}))
loose_s = expect("...and its session", api.post("/v1/embed/sessions", json={"player_token": loose["token"], "parent_origin": ORIGIN}), 201)
LS = loose_s["session"]
check("...which reaches the whole organisation", loose_s.get("scope") == {"tournament": None}, json.dumps(loose_s.get("scope")))
r = api.post(f"/v1/embed/t/{SB}/join", headers=S(LS), json={})
check("a member of one organisation cannot join another's event: no such tournament", r.status_code == 404, r.text[:200])
r = api.get(f"/v1/embed/t/{SB}/me", headers=S(LS))
check("...nor ask about it", r.status_code == 404)
r = api.post(f"/v1/embed/t/{SB}/join", headers=S(FS), json={})
check("an account session made for one organisation cannot join another's", r.status_code == 404, r.text[:200])
r = api.post(f"/v1/embed/t/{CUP}/join", headers=S(by_name["Bea"][1]), json={})
check("a session scoped to one event cannot reach the organisation's others", r.status_code == 404, r.text[:200])
r = api.get(f"/v1/platform/tournaments/{SB}", headers=K)
check("one organisation's key cannot read another's event", r.status_code == 404, r.text[:200])
r = api.post("/v1/platform/player-tokens", headers=K, json={"external_id": "user-1", "name": "Ama", "tournament": SB})
check("...nor scope a token to it", r.status_code == 404)
r = owner.get(f"/v1/orgs/{org_b}")
check("Studio does not show another organisation, or say that it exists", r.status_code == 404)

# The rival's own players do get in, and its arena pairs through the embed.
rb = {}
for ext, name in (("r1", "Rex"), ("r2", "Ria")):
    tk = expect(f"{name}'s token", api.post("/v1/platform/player-tokens", headers=KB, json={"external_id": ext, "name": name}))
    # The rival lists no origins: any page may sign its players in, and need not say which.
    rb[name] = expect(f"{name}'s session", api.post("/v1/embed/sessions", json={"player_token": tk["token"]}), 201)["session"]
    expect(f"{name} joins their own organisation's arena", api.post(f"/v1/embed/t/{SB}/join", headers=S(rb[name]), json={}))
expect("the rival starts it", api.post(f"/v1/platform/tournaments/{SB}/start", headers=KB))
q = expect("Rex asks for a game", api.post(f"/v1/embed/t/{SB}/arena/join", headers=S(rb["Rex"])))
check("...alone, he waits", q["status"] == "waiting")
check("...and can leave the queue", expect("Rex leaves", api.post(f"/v1/embed/t/{SB}/arena/leave", headers=S(rb["Rex"])))
      ["status"] == "left" and sql(f"select count(*) from arena_queue q join tournaments t on t.id = q.tournament_id "
                                   f"where t.slug = '{SB}'") == "0")
expect("Rex comes back", api.post(f"/v1/embed/t/{SB}/arena/join", headers=S(rb["Rex"])))
pr = expect("Ria asks for a game", api.post(f"/v1/embed/t/{SB}/arena/join", headers=S(rb["Ria"])))
check("...paired with Rex at once, the board set up from the queue's answer",
      pr["status"] == "paired" and pr["game"]["status"] == "live" and pr["game"]["position"].startswith("rnbqkbnr"),
      json.dumps(pr)[:300])

# =============================================================================
# The team, blocking, and Studio's other reads
# =============================================================================
expect("the owner invites a teammate by email", owner.post(f"/v1/orgs/{ORG}/members", {"email": "sam@e2e.test", "role": "staff"}), 201)
sam = Player("sam")
confirm(sam)
expect("Sam signs in and loads a page", sam.get("/v1/me"))
check("...which does not, by itself, put them in a team",
      all(o["slug"] != ORG for o in expect("Sam's organisations", sam.get("/v1/orgs"))))
sam_tok = sql("select token from org_invites where email = 'sam@e2e.test'")  # the link in Sam's email
pv = expect("the invitation page shows the team", api.get(f"/v1/invites/by-token/{sam_tok}"))
check("...as a team invitation, the address masked", pv.get("kind") == "org" and pv.get("email_masked") == "s•••@e2e.test")
acc = expect("Sam accepts from the email", sam.post(f"/v1/invites/by-token/{sam_tok}/accept"))
check("...and is in the team", acc.get("kind") == "org" and acc.get("status") == "accepted"
      and any(o["slug"] == ORG and o["role"] == "staff" for o in expect("Sam's organisations now", sam.get("/v1/orgs"))))
check("staff cannot mint keys", sam.post(f"/v1/orgs/{ORG}/keys", {"name": "mine"}).status_code in (403, 404))
expect("Sam is made an admin", owner.patch(f"/v1/orgs/{ORG}/members/{sam.id}", {"role": "admin"}))
check("...and is one", any(o["slug"] == ORG and o["role"] == "admin" for o in expect("again", sam.get("/v1/orgs"))))
expect("and removed", owner.delete(f"/v1/orgs/{ORG}/members/{sam.id}"), 204)
check("...gone", all(o["slug"] != ORG for o in expect("Sam's organisations after", sam.get("/v1/orgs"))))

eve = sql(f"select profile_id from org_players op join organizations o on o.id = op.org_id where o.slug = '{ORG}' and external_id = 'user-5'")
eve_tok = expect("Eve's token", api.post("/v1/platform/player-tokens", headers=K, json={"external_id": "user-5", "name": "Eve"}))
eve_s = expect("Eve's session", api.post("/v1/embed/sessions", json={"player_token": eve_tok["token"], "parent_origin": ORIGIN}),
               201)["session"]
blk = expect("an admin blocks Eve", owner.post(f"/v1/orgs/{ORG}/players/{eve}/block", {"blocked": True}))
check("...by the partner's id", blk.get("external_id") == "user-5")
r = api.get(f"/v1/embed/t/{CUP}/me", headers=S(eve_s))
check("...her session ends at once", r.status_code in (401, 403), r.text[:200])
r = api.post("/v1/platform/player-tokens", headers=K, json={"external_id": "user-5", "name": "Eve"})
check("...and the partner cannot sign her in again", r.status_code == 403, r.text[:200])
ppl = expect("Studio's players", owner.get(f"/v1/orgs/{ORG}/players"))
check("...email invites and the partner's users together", any(p["email"] == "kofi@e2e.test" for p in ppl["players"])
      and any(p.get("external_id") == "user-5" and p["status"] == "blocked" for p in ppl["players"]))
use = expect("the plan's meters", owner.get(f"/v1/orgs/{ORG}/usage"))
check("...from the database's own count", use["plan"] == "club" and use["limits"]["webhooks"] == 5 and use["used"]["webhooks"] == 1
      and use["used"]["keys"] == 1, json.dumps(use)[:300])
ping = api.post("/v1/embed/ping", content=json.dumps({"t": SLUG, "origin": ORIGIN, "view": "standings", "path": "/club"}),
                headers={"Content-Type": "text/plain"})
check("the frame says where it is (text/plain, 204)", ping.status_code == 204, ping.text[:200])
ins = expect("Studio's install check", owner.get(f"/v1/orgs/{ORG}/installs"))
check("...seen on yoursite.example/club, allowed", any(i["origin"] == ORIGIN and i["allowed"] and i["last_path"] == "/club"
                                                       for i in ins), json.dumps(ins)[:300])

ser = expect("a weekly series", owner.post(f"/v1/orgs/{ORG}/series", {
    "title": "Friday Blitz", "weekday": 5, "local_time": "19:00",
    "template": {"game": "chess", "variant": "standard", "format": "arena", "clock_base_s": 180,
                 "clock_increment_s": 2, "arena_minutes": 60}}), 201)
cur = expect("its embed shows the next instance", api.get(f"/v1/embed/o/{ORG}/series/{ser['slug']}"))
check("...open for entries, on a Friday evening in Douala", cur["status"] == "registration"
      and sql(f"select extract(dow from starts_at at time zone 'Africa/Douala') || ' ' || "
              f"to_char(starts_at at time zone 'Africa/Douala', 'HH24:MI') from tournaments where slug = '{cur['slug']}'")
      == "5 19:00")
day = sql(f"select (starts_at at time zone 'Africa/Douala')::date + 7 from tournaments where slug = '{cur['slug']}'")
upd = expect("the organiser skips the Friday after", owner.patch(f"/v1/orgs/{ORG}/series/{ser['id']}", {"skip_dates": [day]}))
check("...noted", day in upd["skip_dates"])
upd = expect("and moves it to 20:00", owner.patch(f"/v1/orgs/{ORG}/series/{ser['id']}", {"local_time": "20:00"}))
check("...for the next instance made", upd["local_time"].startswith("20:00"))
for origin, path in ((ORIGIN, ""), ("https://copycat.example", None)):
    body = {"s": ser["slug"], "o": ORG, "origin": origin, "view": "series", **({} if path is None else {"path": path})}
    ping = api.post("/v1/embed/ping", content=json.dumps(body), headers={"Content-Type": "text/plain"})
    check(f"the loader's beacon names the series, from {origin} (204)", ping.status_code == 204, ping.text[:200])
ins = {(i["origin"], i["view"]): i for i in expect("Studio's install check again", owner.get(f"/v1/orgs/{ORG}/installs"))}
check("...the series seen on the partner's page, allowed, no path kept",
      (ins.get((ORIGIN, "series")) or {}).get("allowed") is True and ins[(ORIGIN, "series")]["last_path"] is None,
      json.dumps(ins.get((ORIGIN, "series"))))
check("...and on a page not on the list, recorded as not allowed",
      (ins.get(("https://copycat.example", "series")) or {}).get("allowed") is False)
sched = expect("the organisation's schedule embed", api.get(f"/v1/embed/o/{ORG}"))
check("...lists the series", any(s["slug"] == ser["slug"] for s in sched["series"]), json.dumps(sched)[:300])

card = expect("the autopilot card of the finished Swiss", owner.get(f"/v1/tournaments/{SLUG}/autopilot"))
check("...remembers what it did", card["enabled"] is True and card["last_action"] is not None and card["platform_enabled"] is True,
      json.dumps(card)[:300])
paused = expect("pause", owner.post(f"/v1/tournaments/{CUP}/autopilot/pause"))
check("...off", paused["enabled"] is False)
expect("resume", owner.post(f"/v1/tournaments/{CUP}/autopilot/resume"))
expect("erasing a user (GDPR)", api.delete("/v1/platform/players/user-4", headers=K), 204)
check("...anonymised, results kept", sql(f"select display_name from profiles where id = '{by_name['Dan'][0]}'") == "Deleted player"
      and sql(f"select count(*) from games where '{by_name['Dan'][0]}' in (white_id, black_id)") == "3")
r = api.get(f"/v1/embed/t/{SLUG}/me", headers=S(by_name["Dan"][1]))
check("...and signed out everywhere", r.status_code == 401)

expect("the organiser revokes the key", owner.delete(f"/v1/orgs/{ORG}/keys/{made_key['id']}"), 204)
r = api.get("/v1/platform/tournaments", headers=K)
check("a revoked key stops at once (401)", r.status_code == 401, r.text[:200])

sys.exit(report())
