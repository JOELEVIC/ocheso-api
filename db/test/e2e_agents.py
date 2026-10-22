#!/usr/bin/env python3
"""
Agents, end to end: an owner builds and hires them through the real API, mints
a key, and a "platform" plays whole games against them with that key - sync,
realtime (the outbox delivered and every payload's signature checked) and
one-off moves - with the real engines.

Local only, like the other e2e suites (db/test/e2e_play.sh sets it up). Needs
Stockfish (STOCKFISH_PATH or on the PATH) and the Maia models.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys

import chess

sys.path.insert(0, os.path.dirname(__file__))
from e2e_harness import Anonymous, Player, api, check, expect, results, sql  # noqa: E402

owner = Player("agent-owner")
other = Player("agent-other")
visitor = Anonymous()

# -----------------------------------------------------------------------------
# The library and building
# -----------------------------------------------------------------------------
lib = expect("anyone can browse the library", visitor.get("/v1/agents/library"))
check("it has archetypes, traits and opening lines",
      len(lib["archetypes"]) >= 10 and "play.style.aggression" in lib["traits"] and "sicilian" in lib["lines"])
health = expect("the engines report themselves", visitor.get("/v1/agents/health"))
check("...on the engine the priors were fitted on", health["stockfish"].get("matchesCalibration") is True, str(health))
sample = expect("an archetype's persona at a rating", visitor.get("/v1/agents/library/grinder?rating=1650"))
check("...is the grinder at 1650", sample["archetype"] == "grinder" and sample["rating"] == 1650)
expect("an unknown archetype is a 422", visitor.get("/v1/agents/library/wizard"), 422)

expect("visitors cannot hire", api.post("/v1/agents", json={"name": "Nope", "archetype": "typical"}), 401)
ama = expect("the owner hires a coffeehouse attacker at 1400",
             owner.post("/v1/agents", {"name": "Ama", "archetype": "coffeehouse", "rating": 1400, "status": "active"}), 201)
check("it is theirs, active, at 1400", ama["status"] == "active" and ama["rating"] == 1400 and ama["archetype"] == "coffeehouse")
bad = owner.post("/v1/agents", {"name": "Bad", "persona": {"rating": 1200, "play": {"style": {"aggression": 3}}}})
check("a persona out of range is refused, naming the field",
      bad.status_code == 422 and "play.style.aggression" in bad.text, bad.text)
bad = owner.post("/v1/agents", {"name": "Bad", "persona": {"rating": 1200, "favouriteColour": "red"}})
check("unknown persona fields are refused", bad.status_code == 422 and "favouriteColour" in bad.text, bad.text)
built = expect("the owner builds one from a persona",
               owner.post("/v1/agents", {"name": "Kojo", "persona": {"rating": 900, "clock": {"tempo": 0.9}}}), 201)
check("built agents start as drafts", built["status"] == "draft" and built["persona"]["clock"]["tempo"] == 0.9)

tuned = dict(ama["persona"])
tuned["play"] = {**tuned["play"], "style": {**tuned["play"]["style"], "aggression": 0.95}}
r = expect("the owner tunes a trait", owner.patch(f"/v1/agents/{ama['id']}", {"persona": tuned, "notes": "sharper"}))
check("...and it sticks", r["persona"]["play"]["style"]["aggression"] == 0.95 and r["notes"] == "sharper")
expect("someone else cannot see it", other.get(f"/v1/agents/{ama['id']}"), 404)
expect("someone else cannot tune it", other.patch(f"/v1/agents/{ama['id']}", {"persona": tuned}), 404)
expect("someone else cannot rename it", other.patch(f"/v1/agents/{ama['id']}", {"name": "Mine"}), 404)
copy = expect("the owner replicates it at 1800", owner.post(f"/v1/agents/{ama['id']}/copy", {"rating": 1800}), 201)
check("the copy keeps its traits, at the new rating",
      copy["rating"] == 1800 and copy["parent_id"] == ama["id"] and copy["persona"]["play"]["style"]["aggression"] == 0.95
      and copy["name"] == "Ama (copy)")
expect("someone else cannot copy it", other.post(f"/v1/agents/{ama['id']}/copy", {}), 404)
mine = expect("the owner lists their agents", owner.get("/v1/agents"))
check("...three of them, with a week of usage each", len(mine) == 3 and all("week" in a for a in mine))
check("others list none", expect("the other lists theirs", other.get("/v1/agents")) == [])

tried = expect("the playground shows what it would play after 1.e4",
               owner.post(f"/v1/agents/{ama['id']}/try", {"moves": ["e2e4"], "samples": 8, "cadence": "5+0"}))
check("...a spread of replies with think times",
      sum(c["count"] for c in tried["choices"]) == 8 and all(c["think_ms"]["max"] >= c["think_ms"]["min"] for c in tried["choices"]),
      json.dumps(tried["choices"])[:300])
expect("an illegal move in the playground is a 422", owner.post(f"/v1/agents/{ama['id']}/try", {"moves": ["e2e5"]}), 422)
diff = expect("the owner gauges a position (untimed)",
              owner.post("/v1/agents/difficulty", {"fen": "r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 4 4",
                                                   "cadence": "untimed", "samples": 40, "ratings": [400, 1200, 2000]}))
check("...mate in one is easy for everyone", diff["bestSan"] == "Qxf7#" and diff["bands"][-1]["pBest"] > 0.9, str(diff)[:300])
timed = expect("...and with a clock nearly out",
               owner.post("/v1/agents/difficulty", {"fen": diff["fen"], "cadence": "3+0", "clock_ms": 4000, "samples": 40,
                                                    "ratings": [400, 1200, 2000]}))
check("time pressure shows in the think times",
      timed["bands"][1]["thinkMs"]["p50"] < diff["bands"][1]["thinkMs"]["p50"],
      f"{timed['bands'][1]['thinkMs']} vs {diff['bands'][1]['thinkMs']}")

# -----------------------------------------------------------------------------
# Keys
# -----------------------------------------------------------------------------
made = expect("the owner makes a key for Ama", owner.post("/v1/agent-keys", {"name": "My platform", "agents": [ama["id"]]}), 201)
KEY = made["key"]
check("it is shown once", KEY.startswith("och_") and made["prefix"] == KEY[:12])
listed = expect("keys list without the key", owner.get("/v1/agent-keys"))
check("...prefix only", listed[0]["prefix"] == KEY[:12] and "key" not in listed[0] and "hash" not in listed[0])
expect("a key cannot cover someone else's agent",
       other.post("/v1/agent-keys", {"name": "Sneaky", "agents": [ama["id"]]}), 400)
expect("keys are renamed", owner.patch(f"/v1/agent-keys/{made['id']}", {"name": "Platform A"}))
H = {"Authorization": f"Bearer {KEY}"}

# -----------------------------------------------------------------------------
# A platform: the key at work
# -----------------------------------------------------------------------------
expect("no key, no agents", api.get("/v1/connect/agents"), 401)
expect("a malformed key is refused before the database", api.get("/v1/connect/agents", headers={"Authorization": "Bearer och_x"}), 401)
expect("an unknown key is refused", api.get("/v1/connect/agents", headers={"Authorization": "Bearer och_" + "0" * 48}), 403)
seen = expect("the key lists what it may drive", api.get("/v1/connect/agents", headers=H))
check("...just Ama", [a["id"] for a in seen] == [ama["id"]])
seen = expect("the key also works as X-Ocheso-Key", api.get("/v1/connect/agents", headers={"X-Ocheso-Key": KEY}))

one_off = expect("a one-off move from the start",
                 api.post(f"/v1/connect/agents/{ama['id']}/move", headers=H, json={"moves": [], "pace": "instant"}))
check("...a legal move, played at once", chess.Move.from_uci(one_off["move"]) in chess.Board().legal_moves
      and one_off["think_ms"] == 0, str(one_off))
expect("a key cannot drive an agent outside its list",
       api.post(f"/v1/connect/agents/{copy['id']}/move", headers=H, json={"moves": []}), 404)

# A whole game, sync: the agent is White, the "platform" plays Black's first legal move each time.
s = expect("the platform seats Ama as White",
           api.post("/v1/connect/sessions", headers=H, json={"agent": ama["id"], "color": "white", "cadence": "3+2",
                                                             "opponent_rating": 1350, "external_ref": "e2e-1"}), 201)
SID = s["session"]["id"]
check("a sync session has no channel", "realtime" not in s["session"])
again = expect("opening the same game again", api.post("/v1/connect/sessions", headers=H, json={
    "agent": ama["id"], "color": "white", "cadence": "3+2", "opponent_rating": 1350, "external_ref": "e2e-1"}), 201)
check("...returns the session it already has", again["session"]["id"] == SID and again["resumed"] is True, str(again)[:200])
board = chess.Board()
clock = 180_000
said: list[str] = []
plies = 0
over = None
while plies < 80:
    out = api.post(f"/v1/connect/sessions/{SID}/move", headers=H,
                   json={"moves": [m.uci() for m in board.move_stack], "clock_ms": clock, "pace": "instant"})
    if out.status_code != 200:
        check(f"move at ply {board.ply()}", False, out.text)
        break
    o = out.json()
    said += [c["intent"] for c in o["chat"]]
    if o["resign"]:
        over = "resigned"
        break
    board.push(chess.Move.from_uci(o["move"]))
    plies += 1
    if board.is_game_over():
        over = board.result()
        break
    board.push(next(iter(board.legal_moves)))
    if board.is_game_over():
        over = board.result()
        break
# Seeds come from the session id, so each run is a different game: it either
# runs the 80 plies or ends properly (mate, resignation) on the way.
check("the agent plays a whole game of legal moves", plies >= 10 or over is not None, f"{plies} plies, {over}")
# The last request again (the platform's retry): the same answer, nothing recorded twice.
# The agent (White) last asked with Black to move gone: one move back if it moved last, two if Black did.
agent_last = len(board.move_stack) - (2 if board.turn == chess.WHITE else 1) if over != "resigned" else len(board.move_stack)
again_moves = [m.uci() for m in board.move_stack[:agent_last]]
again = api.post(f"/v1/connect/sessions/{SID}/move", headers=H, json={"moves": again_moves, "pace": "instant"})
check("a retried request gets the same answer",
      again.status_code == 200 and (again.json()["move"] == (board.move_stack[agent_last].uci() if agent_last < len(board.move_stack) else None)),
      again.text[:200])
older = api.post(f"/v1/connect/sessions/{SID}/move", headers=H, json={"moves": [], "pace": "instant"})
check("an older position is refused", older.status_code == 409 and "already moved" in older.text, older.text)
wrong = api.post(f"/v1/connect/sessions/{SID}/move", headers=H, json={"moves": ["e2e4"], "pace": "instant"})
check("asking the agent to move for the other side is a 409", wrong.status_code == 409, wrong.text)
draw = expect("the platform offers a draw", api.post(f"/v1/connect/sessions/{SID}/draw", headers=H))
check("...and gets an answer, a beat later", isinstance(draw["accept"], bool) and 1500 <= draw["after_ms"] <= 6000)
end = expect("the platform ends the game", api.post(f"/v1/connect/sessions/{SID}/end", headers=H, json={"result": "win"}))
check("...the session is finished", end["session"]["status"] == "finished" and end["session"]["result"] == "win")
expect("no moves after the end", api.post(f"/v1/connect/sessions/{SID}/move", headers=H, json={"moves": [], "pace": "instant"}), 409)
seen = expect("the owner sees the session", owner.get(f"/v1/agents/{ama['id']}/sessions"))
check("...with its plies and result", seen[0]["external_ref"] == "e2e-1" and seen[0]["plies"] == plies + (1 if over == "resigned" else 0) and seen[0]["result"] == "win",
      str(seen[0]))
check("...but never its secret or channel", "secret" not in seen[0] and "channel" not in seen[0])

# Human pace: the answer says when to play it.
s2 = expect("a second session, Black this time",
            api.post("/v1/connect/sessions", headers=H, json={"agent": ama["id"], "color": "black", "cadence": "10+0"}), 201)
o = expect("a human-paced reply to 1.d4", api.post(f"/v1/connect/sessions/{s2['session']['id']}/move", headers=H,
                                                  json={"moves": ["d2d4"], "clock_ms": 600_000}))
check("...with a think time and when to play it", o["think_ms"] > 0 and o["play_at"] > 0 and o["move"], str(o))

# Realtime: 202 at once; the move arrives on the channel, signed.
rt = expect("a realtime session", api.post("/v1/connect/sessions", headers=H,
                                           json={"agent": ama["id"], "color": "white", "cadence": "5+0", "realtime": True}), 201)
RT = rt["session"]["realtime"]
check("...returns a channel, the public key and a secret",
      RT["topic"].startswith("agent:") and len(RT["secret"]) == 64 and RT["key"] and RT["url"])
before = sql("select count(*) from realtime.sent")
acc = api.post(f"/v1/connect/sessions/{rt['session']['id']}/move", headers=H, json={"moves": [], "pace": "hasty"})
check("the move request is accepted for delivery", acc.status_code == 202 and acc.json()["delivery"] == "realtime", acc.text)
# Already due (a quick move, a slow request) goes out at once; otherwise it waits for the tick.
queued = sql("select count(*) from private.agent_outbox")
check("it is either sent or waiting in the outbox", queued in ("0", "1"), queued)
sql("update private.agent_outbox set deliver_at = now()")
sql("select private.deliver_agent_outbox()")
sent = json.loads(sql(f"select payload from realtime.sent where topic = '{RT['topic']}' order by id desc limit 1") or "null")
check("it is broadcast on the session's channel", sent is not None and int(sql("select count(*) from realtime.sent")) == int(before) + 1)
if sent:
    data = sent["data"]
    good = hmac.new(RT["secret"].encode(), json.dumps(data, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    check("the payload verifies with the session secret", hmac.compare_digest(sent["sig"], good))
    check("...and carries the move", chess.Move.from_uci(data["move"]) in chess.Board().legal_moves and data["ply"] == 0)

# The people around the agents: presence, seats, challenges, friend requests.
pres = expect("the key sees who is online", api.get("/v1/connect/presence", headers=H))
mine = [a for a in pres["agents"] if a["id"] == ama["id"]]
check("...each agent with its cadences and either a session now or the next one",
      len(mine) == 1 and mine[0]["cadences"] and (mine[0]["online"] or mine[0]["next_online"]), str(mine))
check("...and personas never leave the API", all("persona" not in a for a in pres["agents"]))
forced = expect("a platform testing can set the schedule aside", api.get("/v1/connect/presence?ignore_schedule=true", headers=H))
check("...then an active agent is online", [a["online"] for a in forced["agents"] if a["id"] == ama["id"]] == [True])
import time as _t
now_ms = int(_t.time() * 1000)
seek = {"id": "seek-e2e-1", "creator_id": "person-1", "creator_rating": 1450, "cadence": "5+0",
        "created_at_ms": now_ms - 40_000, "heartbeat_at_ms": now_ms - 1_000}
took = expect("a seek that waited 40 s with nobody else around",
              api.post("/v1/connect/seat", headers=H, json={"seek": seek, "agents": [{"id": ama["id"], "idle": True}], "ignore_schedule": True}))
check("...is taken by the agent", took == {"action": "take", "reason": None, "agent": ama["id"], "candidates": 1}, str(took))
young = expect("a seek two seconds old", api.post("/v1/connect/seat", headers=H, json={
    "seek": {**seek, "id": "seek-e2e-2", "created_at_ms": now_ms - 2_000}, "agents": [{"id": ama["id"], "idle": True}], "ignore_schedule": True}))
check("...waits for a person first", young["action"] == "wait" and young["reason"] == "people-first-window" and young["retry_in_ms"] > 0, str(young))
paired = expect("a seek another person could still pair with", api.post("/v1/connect/seat", headers=H, json={
    "seek": {**seek, "id": "seek-e2e-3", "human_alternatives": 1}, "agents": [{"id": ama["id"], "idle": True}], "ignore_schedule": True}))
check("...is left to people", paired["action"] == "wait" and paired["reason"] == "a-person-could-pair", str(paired))
busy = expect("an agent already playing", api.post("/v1/connect/seat", headers=H, json={
    "seek": {**seek, "id": "seek-e2e-4"}, "agents": [{"id": ama["id"], "idle": False}], "ignore_schedule": True}))
check("...never takes a second game", busy["action"] == "wait" and busy["reason"] == "nobody-suitable", str(busy))
foreign = expect("an agent the key does not cover", api.post("/v1/connect/seat", headers=H, json={
    "seek": {**seek, "id": "seek-e2e-5"}, "agents": [{"id": copy["id"], "idle": True}], "ignore_schedule": True}))
check("...is never seated", foreign["action"] == "wait", str(foreign))
ch = expect("a person challenges the agent at its cadence", api.post(f"/v1/connect/agents/{ama['id']}/challenge", headers=H, json={
    "challenge_id": "ch-1", "challenger_rating": 1450, "cadence": "5+0", "ignore_schedule": True}))
check("...it accepts, a beat later", ch["action"] == "accept" and 4_000 <= ch["after_ms"] <= 20_000, str(ch))
ch2 = expect("...and at a cadence it doesn't play", api.post(f"/v1/connect/agents/{ama['id']}/challenge", headers=H, json={
    "challenge_id": "ch-2", "challenger_rating": 1450, "cadence": "1+0", "ignore_schedule": True}))
check("...it declines or lets it sit", ch2["action"] in ("decline", "ignore"), str(ch2))
ch3 = expect("...or while in a game", api.post(f"/v1/connect/agents/{ama['id']}/challenge", headers=H, json={
    "challenge_id": "ch-3", "challenger_rating": 1450, "cadence": "5+0", "idle": False, "ignore_schedule": True}))
check("...it lets it sit", ch3["action"] == "ignore", str(ch3))
fr = expect("a friend request", api.post(f"/v1/connect/agents/{ama['id']}/friend-request", headers=H, json={"request_id": "fr-1"}))
check("...is answered later, not at once", isinstance(fr["accept"], bool) and fr["after_ms"] >= 60_000, str(fr))
expect("an agent outside the key cannot be challenged", api.post(f"/v1/connect/agents/{copy['id']}/challenge", headers=H, json={
    "challenge_id": "ch-4", "challenger_rating": 1450, "cadence": "5+0"}), 404)

# The owner's controls bite at once.
expect("the owner pauses Ama", owner.patch(f"/v1/agents/{ama['id']}", {"status": "paused"}))
paused = api.post(f"/v1/connect/sessions/{s2['session']['id']}/move", headers=H, json={"moves": ["d2d4", o["move"], "c2c4"]})
check("a paused agent stops mid-game", paused.status_code == 409 and "paused" in paused.text, paused.text)
expect("...but its game can still be ended", api.post(f"/v1/connect/sessions/{s2['session']['id']}/end", headers=H,
                                                      json={"result": "aborted"}))
expect("the owner reactivates Ama", owner.patch(f"/v1/agents/{ama['id']}", {"status": "active"}))

gauged = expect("the key gauges a position", api.post("/v1/connect/difficulty", headers=H,
                                                      json={"moves": ["e2e4", "e7e5", "g1f3"], "samples": 20, "ratings": [800, 1600]}))
check("...band by band", [b["rating"] for b in gauged["bands"]] == [800, 1600])

usage = expect("the owner sees usage", owner.get(f"/v1/agents/{ama['id']}/usage"))
check("...moves and sessions counted today", usage and usage[-1]["moves"] >= plies + 2 and usage[-1]["sessions"] == 3, str(usage))

expect("the owner revokes the key", owner.delete(f"/v1/agent-keys/{made['id']}"), 204)
expect("a revoked key stops at once", api.get("/v1/connect/agents", headers=H), 403)
expect("someone else cannot delete Ama", other.delete(f"/v1/agents/{ama['id']}"), 404)
expect("the owner deletes the copy", owner.delete(f"/v1/agents/{copy['id']}"), 204)

failed = [r for r in results if not r[0]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
