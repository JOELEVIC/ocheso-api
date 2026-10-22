#!/usr/bin/env python3
"""
Whole tournaments, played through the real API against a real PostgREST.

Local only: a throwaway database with the Supabase shim, PostgREST in front of
it, and test players whose tokens are minted with a local secret. Nothing here
touches a real project.

    db/test/e2e_play.sh        # sets up the database and PostgREST, runs this

Every move goes through POST /v1/games/{id}/move: judged by the rules engine,
signed, verified and clocked by the database. Draughts games are played to the
end with moves chosen at random from the legal list the server publishes, so
the list and the referee are checked against each other on every move.
"""

from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from e2e_harness import Player, api, check, expect, results, sql, tournament  # noqa: E402

def by_id(players: list[Player]) -> dict[str, Player]:
    return {p.id: p for p in players}


def play_random(game_id: str, people: dict[str, Player], rng: random.Random, max_plies: int = 400) -> dict:
    """Plays legal moves chosen at random until the game ends (or resigns at the cap)."""
    viewer = next(iter(people.values()))
    for _ in range(max_plies):
        state = viewer.get(f"/v1/games/{game_id}").json()["game"]
        if state["status"] == "finished":
            return state
        mover = people[state["white_id"] if state["turn"] == "white" else state["black_id"]]
        move = rng.choice(state["legal"])
        r = mover.post(f"/v1/games/{game_id}/move", {"move": move, "ply": state["ply"]})
        if r.status_code != 200:
            check(f"legal move {move} accepted", False, r.text)
            return state
    state = viewer.get(f"/v1/games/{game_id}").json()["game"]
    mover = people[state["white_id"] if state["turn"] == "white" else state["black_id"]]
    mover.post(f"/v1/games/{game_id}/resign")
    return viewer.get(f"/v1/games/{game_id}").json()["game"]


def round_games(viewer: Player, slug: str, number: int) -> list[dict]:
    rounds = viewer.get(f"/v1/tournaments/{slug}/rounds").json()
    return next(r for r in rounds if r["number"] == number)["games"]


rng = random.Random(42)
owner = Player("Owen")
chess_players = [Player(n) for n in ("Ada", "Ben", "Cy", "Dee", "Eve")]
people = by_id(chess_players + [owner])

# -----------------------------------------------------------------------------
# A five-player Swiss in chess: byes, the referee, draws, the clock.
# -----------------------------------------------------------------------------
slug = tournament(owner, chess_players, title="E2E Swiss", rounds_count=3)
expect("a player cannot pair rounds", chess_players[0].post(f"/v1/tournaments/{slug}/rounds/next", {"start": True}), 404)
expect("round 1 paired and started", owner.post(f"/v1/tournaments/{slug}/rounds/next", {"start": True}))
games = round_games(owner, slug, 1)
check("five players: two boards and a bye", sum(g["black"] is None for g in games) == 1 and len(games) == 3)
expect("round 2 waits for round 1", owner.post(f"/v1/tournaments/{slug}/rounds/next", {"start": True}), 409)

board1 = next(g for g in games if g["board"] == 1)
g1 = owner.get(f"/v1/games/{board1['id']}").json()["game"]
white, black = people[g1["white_id"]], people[g1["black_id"]]
expect("Black cannot move first", black.post(f"/v1/games/{g1['id']}/move", {"move": "e7e5"}), 409)
expect("an illegal move is refused", white.post(f"/v1/games/{g1['id']}/move", {"move": "e2e5"}), 422)
expect("a spectator cannot move", owner.post(f"/v1/games/{g1['id']}/move", {"move": "e2e4"}), 403)
for i, mv in enumerate(["e2e4", "e7e5", "d1h5", "b8c6", "f1c4", "g8f6"]):
    expect(f"scholar's mate, move {i + 1}", (white if i % 2 == 0 else black).post(f"/v1/games/{g1['id']}/move", {"move": mv, "ply": i}))
expect("a stale ply is refused", white.post(f"/v1/games/{g1['id']}/move", {"move": "h5f7", "ply": 3}), 409)
done = expect("Qxf7 mates", white.post(f"/v1/games/{g1['id']}/move", {"move": "h5f7", "ply": 6}))
check("checkmate is recorded as a win for White", (done["result"], done["termination"]) == ("white", "checkmate"), str(done))
view = owner.get(f"/v1/games/{g1['id']}").json()
check("the move list reads as written", [m["san"] for m in view["moves"]] == ["e4", "e5", "Qh5", "Nc6", "Bc4", "Nf6", "Qxf7#"])

board2 = next(g for g in games if g["board"] == 2)
g2 = owner.get(f"/v1/games/{board2['id']}").json()["game"]
w2, b2 = people[g2["white_id"]], people[g2["black_id"]]
expect("a flag cannot be claimed with time left", b2.post(f"/v1/games/{g2['id']}/flag"), 409)
sql(f"update games set turn_started_at = now() - interval '6 minutes' where id = '{g2['id']}'")
expect("a move after the flag falls is refused", w2.post(f"/v1/games/{g2['id']}/move", {"move": "e2e4"}), 409)
flagged = expect("Black claims the flag", b2.post(f"/v1/games/{g2['id']}/flag"))
check("out of time loses", (flagged["result"], flagged["termination"]) == ("black", "timeout"), str(flagged))

for r in (2, 3):
    expect(f"round {r} paired", owner.post(f"/v1/tournaments/{slug}/rounds/next", {"start": False}))
    rid = next(x for x in owner.get(f"/v1/tournaments/{slug}/rounds").json() if x["number"] == r)["id"]
    expect(f"round {r} started", owner.post(f"/v1/rounds/{rid}/start"))
    for g in round_games(owner, slug, r):
        if g["black"] is None:
            continue
        if rng.random() < 0.5:
            expect("draw offered", people[g["white"]["id"]].post(f"/v1/games/{g['id']}/draw"))
            expect("draw accepted", people[g["black"]["id"]].post(f"/v1/games/{g['id']}/draw"))
        else:
            expect("resigns", people[g["black"]["id"]].post(f"/v1/games/{g['id']}/resign"))
expect("no fourth round in a three-round Swiss", owner.post(f"/v1/tournaments/{slug}/rounds/next", {}), 409)
table = expect("standings", api.get(f"/v1/tournaments/{slug}/standings"))
check("everyone is on the table", len(table["lines"]) == 5)
check("points add up: one per game, one per bye", sum(l["points"] for l in table["lines"]) == 3 * 3)
met = [frozenset((g["white"]["id"], g["black"]["id"])) for r in owner.get(f"/v1/tournaments/{slug}/rounds").json()
       for g in r["games"] if g["black"]]
check("nobody met twice", len(met) == len(set(met)))
byes = [g["white"]["id"] for r in owner.get(f"/v1/tournaments/{slug}/rounds").json() for g in r["games"] if g["black"] is None]
check("three different players had the bye", len(set(byes)) == 3)

# -----------------------------------------------------------------------------
# A knockout in international draughts, played to the end at random.
# -----------------------------------------------------------------------------
ko = [Player(n) for n in ("Kim", "Lou", "Max", "Nia")]
people |= by_id(ko)
slug = tournament(owner, ko, title="E2E Knockout", game="checkers", variant="international", format="knockout")
champion = None
for step in range(12):
    r = owner.post(f"/v1/tournaments/{slug}/rounds/next", {"start": True})
    if r.status_code == 409 and "complete" in r.text:
        break
    expect(f"knockout step {step + 1} paired", r)
    rounds = owner.get(f"/v1/tournaments/{slug}/rounds").json()
    for g in rounds[-1]["games"]:
        if g["status"] != "finished" and g["black"]:
            end = play_random(g["id"], people, rng)
            check(f"draughts game ends by the rules ({end['termination']})",
                  end["termination"] in {"no_moves", "repetition", "twenty_five_moves", "resignation"}, str(end["termination"]))
table = api.get(f"/v1/tournaments/{slug}/standings").json()
check("the knockout crowns one champion", table["champion"] in {p.id for p in ko}, str(table.get("champion")))

# -----------------------------------------------------------------------------
# An arena in Brazilian draughts.
# -----------------------------------------------------------------------------
ar = [Player(n) for n in ("Oli", "Pia", "Quin")]
people |= by_id(ar)
slug = tournament(owner, ar, title="E2E Arena", game="checkers", variant="brazilian", format="arena", arena_minutes=30)
first = expect("the first player waits", ar[0].post(f"/v1/tournaments/{slug}/arena/join"))
check("alone in the queue, you wait", first["status"] == "waiting")
second = expect("the second player is paired at once", ar[1].post(f"/v1/tournaments/{slug}/arena/join"))
check("paired with the one waiting", second["status"] == "paired" and {second["game"]["white_id"], second["game"]["black_id"]} == {ar[0].id, ar[1].id})
mid = expect("asking again mid-game", ar[0].post(f"/v1/tournaments/{slug}/arena/join"))
check("asking mid-game returns the game you are in, not a second one",
      mid["status"] == "paired" and mid["game"]["id"] == second["game"]["id"])
end = play_random(second["game"]["id"], people, rng)
check("the arena game finishes", end["status"] == "finished")
expect("the third player waits", ar[2].post(f"/v1/tournaments/{slug}/arena/join"))
again = expect("a finished player is paired again", ar[0].post(f"/v1/tournaments/{slug}/arena/join"))
check("paired with whoever is free", again["status"] == "paired")
table = api.get(f"/v1/tournaments/{slug}/standings").json()
check("arena scores are on the table", table["format"] == "arena" and len(table["lines"]) == 3)

failed = [r for r in results if not r[0]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
