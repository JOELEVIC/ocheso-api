#!/usr/bin/env python3
"""
Every way of running a tournament that is not playing it, through the real API.

The owner, a co-admin, a moderator, players, a stranger and an anonymous
visitor each try what their role allows and what it does not: settings, staff,
the entry code and invite link, entries in every state, capacity, visibility,
the lifecycle, adding players, and profiles.

    db/test/e2e_play.sh        # runs this suite and the play suite
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from e2e_harness import Anonymous, Player, check, expect, report  # noqa: E402

owner, co, mod = Player("Olive"), Player("Corin"), Player("Moira")
p1, p2, p3, p4 = Player("Pax"), Player("Quill"), Player("Rue"), Player("Sol")
stranger, anon = Player("Stray"), Anonymous()
name = {p.id: p for p in (owner, co, mod, p1, p2, p3, p4, stranger)}
for p in name.values():
    p.username = p.get("/v1/me").json()["username"]

# -----------------------------------------------------------------------------
# Profiles
# -----------------------------------------------------------------------------
me = expect("a profile is made at sign-up", p1.get("/v1/me"))
check("with a username and the name from sign-up", me["username"].startswith("pax_") and me["display_name"] == "Pax")
expect("display name, username and country can be changed",
       p1.patch("/v1/me", {"display_name": "Pax Romana", "username": "pax_romana", "country": "CM"}))
p1.username = "pax_romana"
check("and are read back", p1.get("/v1/me").json()["display_name"] == "Pax Romana")
expect("a taken username is refused", p2.patch("/v1/me", {"username": "pax_romana"}), 409)
expect("ratings cannot be typed in", p1.patch("/v1/me", {"chess_rating": 2800}), 422)
expect("anyone can look a player up by username", anon.get("/v1/profiles/pax_romana"))
expect("a visitor has no /me", anon.get("/v1/me"), 401)

# -----------------------------------------------------------------------------
# A draft, and who can see it
# -----------------------------------------------------------------------------
t = expect("the owner creates a draft", owner.post("/v1/tournaments", {
    "title": "Manage Test", "game": "chess", "variant": "standard", "format": "swiss",
    "clock_base_s": 600, "clock_increment_s": 5, "starts_at": "2030-01-01T10:00:00Z", "rounds_count": 5,
}), 201)
slug = t["slug"]
T = f"/v1/tournaments/{slug}"
check("it starts as a draft", t["status"] == "draft")
expect("a visitor cannot open a draft", anon.get(T), 404)
expect("nor can a stranger", stranger.get(T), 404)
check("drafts are not in the directory", slug not in [x["slug"] for x in anon.get("/v1/tournaments").json()])
check("the owner sees it under their tournaments",
      any(m["tournament"]["slug"] == slug and m["my_role"] == "owner" for m in owner.get("/v1/tournaments/mine").json()))

# -----------------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------------
changed = expect("the owner changes the settings", owner.patch(T, {
    "title": "Manage Test Open", "description": "Prizes for the top three.", "clock_base_s": 900,
    "clock_increment_s": 10, "rounds_count": 3, "max_participants": 3,
    "tiebreaks": ["sonneborn_berger", "buchholz", "wins"],
}))
check("every setting is kept", (changed["title"], changed["clock_base_s"], changed["rounds_count"], changed["max_participants"],
                                changed["tiebreaks"]) == ("Manage Test Open", 900, 3, 3, ["sonneborn_berger", "buchholz", "wins"]))
expect("a stranger cannot change them", stranger.patch(T, {"title": "Hijacked"}), 404)
expect("status is not a setting", owner.patch(T, {"status": "live"}), 422)
expect("nor is the owner", owner.patch(T, {"owner_id": stranger.id}), 422)
expect("nor is the game being played", owner.patch(T, {"game": "checkers"}), 422)
expect("an empty change is refused", owner.patch(T, {}), 400)

# -----------------------------------------------------------------------------
# Staff
# -----------------------------------------------------------------------------
expect("the owner appoints a co-admin by username", owner.post(f"{T}/staff", {"username": co.username, "role": "co_admin"}), 201)
mod_row = expect("and a moderator", owner.post(f"{T}/staff", {"username": mod.username, "role": "moderator"}), 201)
expect("the owner cannot appoint themselves", owner.post(f"{T}/staff", {"username": owner.username, "role": "co_admin"}), 409)
expect("nobody unknown can be appointed", owner.post(f"{T}/staff", {"username": "no_such_person", "role": "moderator"}), 404)
expect("a co-admin cannot appoint staff", co.post(f"{T}/staff", {"username": p4.username, "role": "moderator"}), 403)
check("staff see the draft", co.get(T).status_code == 200 and mod.get(T).status_code == 200)
check("staff see each other", len(mod.get(f"{T}/staff").json()) == 2)
check("the co-admin's list shows their role",
      any(m["tournament"]["slug"] == slug and m["my_role"] == "co_admin" for m in co.get("/v1/tournaments/mine").json()))
expect("the owner promotes the moderator", owner.patch(f"{T}/staff/{mod_row['id']}", {"role": "co_admin"}))
expect("and demotes them again", owner.patch(f"{T}/staff/{mod_row['id']}", {"role": "moderator"}))
expect("a co-admin cannot change roles", co.patch(f"{T}/staff/{mod_row['id']}", {"role": "co_admin"}), 404)

# -----------------------------------------------------------------------------
# Access: the code and the invite link
# -----------------------------------------------------------------------------
access = expect("a co-admin reads the access settings", co.get(f"{T}/access"))
expect("a moderator cannot", mod.get(f"{T}/access"), 404)
expect("nor can a stranger", stranger.get(f"{T}/access"), 404)
expect("the co-admin sets an entry code", co.put(f"{T}/access/code", {"entry_code": "open24"}))
check("codes are kept in capitals", co.get(f"{T}/access").json()["entry_code"] == "OPEN24")
expect("a malformed code is refused", co.put(f"{T}/access/code", {"entry_code": "no!"}), 422)
expect("the co-admin requires the code", co.patch(T, {"requires_code": True}))
expect("a moderator cannot change settings", mod.patch(T, {"requires_code": False}), 404)
old_invite = access["invite_token"]
rotated = expect("the owner replaces the invite link", owner.post(f"{T}/access/invite/rotate"))
check("the new link is different", rotated["invite_token"] != old_invite and slug in rotated["invite_url"])

# -----------------------------------------------------------------------------
# Opening entries; joining every way
# -----------------------------------------------------------------------------
expect("a moderator cannot open entries", mod.post(f"{T}/publish"), 404)
expect("the co-admin opens entries", co.post(f"{T}/publish"))
check("an open, listed event is in the directory", slug in [x["slug"] for x in anon.get("/v1/tournaments").json()])
expect("joining without the code is refused", p1.post(f"{T}/join", {}), 403)
expect("joining with the wrong code is refused", p1.post(f"{T}/join", {"code": "WRONG1"}), 403)
j1 = expect("joining with the code, in lower case, works", p1.post(f"{T}/join", {"code": "open24"}))
check("approved at once while approval is off", (j1["status"], j1["joined_via"]) == ("approved", "code"))
expect("the owner turns approval on", owner.patch(T, {"auto_approve": False}))
j2 = expect("the next entry waits", p2.post(f"{T}/join", {"code": "OPEN24"}))
check("as pending", j2["status"] == "pending")
check("a player cannot see someone else's pending entry", p2.id not in [e["user_id"] for e in p1.get(f"{T}/participants").json()])
check("staff see every entry", len(mod.get(f"{T}/participants").json()) == 2)
expect("a player cannot approve themselves", p2.post(f"/v1/participants/{j2['id']}/approve"), 404)
expect("the moderator approves", mod.post(f"/v1/participants/{j2['id']}/approve"))
j3 = expect("another entry waits", p3.post(f"{T}/join", {"code": "OPEN24"}))
expect("the moderator declines it", mod.post(f"/v1/participants/{j3['id']}/reject"))
check("joining again does not undo a decline", p3.post(f"{T}/join", {"code": "OPEN24"}).json()["status"] == "rejected")
expect("the co-admin approves it after all", co.post(f"/v1/participants/{j3['id']}/approve"))
expect("the event is full: an invite cannot squeeze past the cap",
       p4.post(f"{T}/join", {"invite": rotated["invite_token"]}), 409)
expect("nor can the owner add a fourth", owner.post(f"{T}/participants", {"username": p4.username}), 409)
expect("a moderator cannot remove anyone", mod.delete(f"/v1/participants/{j3['id']}"), 404)
expect("the co-admin removes one", co.delete(f"/v1/participants/{j3['id']}"), 204)
expect("an old invite link no longer gets you in", p4.post(f"{T}/join", {"invite": old_invite}), 403)
j4 = expect("the current invite link does, past code and approval", p4.post(f"{T}/join", {"invite": rotated["invite_token"]}))
check("approved, by invite", (j4["status"], j4["joined_via"]) == ("approved", "invite"))
w = expect("a player withdraws", p2.post(f"{T}/withdraw"))
check("withdrawn", w["status"] == "withdrawn")
added = expect("the owner adds someone by username", owner.post(f"{T}/participants", {"username": "@" + p3.username}))
check("approved, as added", (added["status"], added["joined_via"]) == ("approved", "added"))
expect("a stranger cannot add players", stranger.post(f"{T}/participants", {"username": p2.username}), 404)

# -----------------------------------------------------------------------------
# What visitors see
# -----------------------------------------------------------------------------
roster = anon.get(f"{T}/roster").json()
check("visitors see the players of a listed event", {r["user_id"] for r in roster} == {p1.id, p3.id, p4.id})
check("and their names, never their emails", all("email" not in r for r in roster) and any(r["display_name"] == "Pax Romana" for r in roster))
expect("the owner hides the player list", owner.patch(T, {"participants_visible": False}))
check("hidden from visitors", anon.get(f"{T}/roster").json() == [])
check("not from players", len(p1.get(f"{T}/roster").json()) == 3)
expect("the owner unlists it", owner.patch(T, {"is_listed": False, "participants_visible": True}))
check("unlisted: out of the directory", slug not in [x["slug"] for x in anon.get("/v1/tournaments").json()])
expect("but still open by its link", anon.get(T))
check("and people with the link see its players, as with a listed one", len(anon.get(f"{T}/roster").json()) == 3)
expect("listed again", owner.patch(T, {"is_listed": True}))

# -----------------------------------------------------------------------------
# The lifecycle
# -----------------------------------------------------------------------------
expect("a published event cannot be deleted", owner.delete(T), 404)
expect("entries can be closed again: back to draft", owner.post(f"{T}/unpublish"))
expect("a stranger cannot see it once it is a draft again", stranger.get(T), 404)
expect("reopened", owner.post(f"{T}/publish"))
expect("a moderator cannot start it", mod.post(f"{T}/start"), 404)
started = expect("the owner starts it", owner.post(f"{T}/start"))
check("live, and stamped with when", started["status"] == "live" and started["started_at"])
expect("nobody joins after the start", p2.post(f"{T}/join", {"code": "OPEN24"}), 409)
expect("nor can anyone be added", owner.post(f"{T}/participants", {"username": p2.username}), 409)
r = p1.post(f"{T}/withdraw")
check("nor withdraw, and the reason is given", r.status_code == 409 and "started" in r.text, r.text)
expect("a live event cannot go back to draft", owner.post(f"{T}/unpublish"), 409)
expect("the co-admin marks it finished", co.post(f"{T}/finish"))
expect("finished cannot restart", owner.post(f"{T}/start"), 409)
archived = expect("the owner archives it", owner.post(f"{T}/archive"))
check("archived", archived["status"] == "archived")

d = expect("another draft", owner.post("/v1/tournaments", {
    "title": "Throwaway", "game": "checkers", "variant": "brazilian", "format": "arena",
    "clock_base_s": 180, "starts_at": "2030-01-01T10:00:00Z", "arena_minutes": 45,
}), 201)
expect("a stranger cannot delete it", stranger.delete(f"/v1/tournaments/{d['slug']}"), 404)
expect("the owner deletes it", owner.delete(f"/v1/tournaments/{d['slug']}"), 204)
expect("it is gone", owner.get(f"/v1/tournaments/{d['slug']}"), 404)
expect("a code-only event without a code is refused at creation", owner.post("/v1/tournaments", {
    "title": "Bad", "game": "chess", "variant": "standard", "format": "swiss", "clock_base_s": 300,
    "starts_at": "2030-01-01T10:00:00Z", "rounds_count": 3, "requires_code": True,
}), 422)

sys.exit(1 if report() else 0)
