#!/usr/bin/env python3
"""
Tries to cheat at db/play.sql, and asserts that it cannot.

Every check runs as a real Postgres role with a JWT subject, as test_rls.py
does. Rulings are signed the way play/referee.py signs them, with the key read
from the database as the superuser - which is the only way to get it.

    python3 db/test/test_play.py [postgres-url]

Needs supabase_shim.sql, schema.sql and play.sql applied.
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

OWNER, A, B, C, D, STRANGER = (str(uuid.uuid4()) for _ in range(6))
ANON = "anon"
START = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
AFTER_E4 = "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1"

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


def value(statement: str) -> str:
    ok, out = sql(statement)
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


def ruling(kind: str, by: str, body: dict, ttl: int = 60, key: str | None = None) -> str:
    payload = json.dumps({**body, "kind": kind, "by": by, "exp": int(time.time()) + ttl},
                         separators=(",", ":"), sort_keys=True)
    sig = hmac.new((key or SECRET).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"'{payload}', '{sig}'"


# -----------------------------------------------------------------------------
# Setup: a live Swiss with four approved players, plus a stranger.
# -----------------------------------------------------------------------------
value(
    "insert into auth.users (id, email) values "
    + ",".join(f"('{u}', '{n}@ocheso.test')" for u, n in
               [(OWNER, "owner"), (A, "a"), (B, "b"), (C, "c"), (D, "d"), (STRANGER, "stranger")])
)
TID = value(
    f"insert into tournaments (owner_id, title, game, variant, format, clock_base_s, clock_increment_s, starts_at, rounds_count) "
    f"values ('{OWNER}', 'Play Test', 'chess', 'standard', 'swiss', 300, 2, now(), 3) returning id"
)
value(f"update tournaments set status = 'registration' where id = '{TID}'")
value("insert into participants (tournament_id, user_id, status) values "
      + ",".join(f"('{TID}', '{u}', 'approved')" for u in (A, B, C, D)))

# -----------------------------------------------------------------------------
check("the referee's key is unreadable to players",
      not sql("select secret from private.referee", A)[0])
check("the referee's key is unreadable to visitors",
      not sql("select secret from private.referee", ANON)[0])
denied("a player cannot verify rulings for themselves",
       "select private.ruling('{}', 'x', 'move')", A)

pairings = {"tournament": TID, "round": 1, "start": False, "games": [
    {"board": 1, "white": A, "black": B, "position": START, "turn": "white", "legal": ["e2e4"]},
    {"board": 2, "white": C, "black": D, "position": START, "turn": "white", "legal": ["e2e4"]},
]}
denied("nothing is paired before the tournament starts",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, pairings)})", OWNER, "not under way")
value(f"update tournaments set status = 'live' where id = '{TID}'")
check("going live stamps the start", value(f"select started_at is not null from tournaments where id = '{TID}'") == "t")

denied("pairings signed with the wrong key are refused",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, pairings, key='0' * 64)})", OWNER, "did not sign")
denied("an expired ruling is refused",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, pairings, ttl=-5)})", OWNER, "expired")
denied("a ruling made for someone else is refused",
       f"select count(*) from publish_pairings({ruling('pairings', A, pairings)})", OWNER, "someone else")
denied("a ruling of another kind is refused",
       f"select count(*) from publish_pairings({ruling('move', OWNER, pairings)})", OWNER, "something else")
denied("a player cannot publish pairings, even with a genuine ruling",
       f"select count(*) from publish_pairings({ruling('pairings', A, pairings)})", A, "no such tournament")
bad = {**pairings, "games": [{"board": 1, "white": A, "black": STRANGER, "position": START, "turn": "white"}]}
denied("only approved entrants can be paired",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, bad)})", OWNER, "approved")
twice = {**pairings, "games": [pairings["games"][0], {**pairings["games"][1], "white": A}]}
denied("nobody is paired twice in a round",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, twice)})", OWNER, "twice")
skip = {**pairings, "round": 2}
denied("rounds cannot be skipped",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, skip)})", OWNER, "next round")

allowed("the owner publishes round one", f"select count(*) from publish_pairings({ruling('pairings', OWNER, pairings)})", OWNER, "2")
denied("a round cannot be paired twice",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, pairings)})", OWNER, "already paired")
G1 = value(f"select id from games where tournament_id = '{TID}' and board = 1")
G2 = value(f"select id from games where tournament_id = '{TID}' and board = 2")
RID = value(f"select id from rounds where tournament_id = '{TID}' and number = 1")
check("published without starting, the clocks are still", value(f"select status from games where id = '{G1}'") == "scheduled")
denied("the next round waits for this one",
       f"select count(*) from publish_pairings({ruling('pairings', OWNER, {**pairings, 'round': 2})})", OWNER, "current round")
denied("a player cannot start the round", f"select start_round('{RID}')", A)
allowed("the owner starts the round", f"select status from start_round('{RID}')", OWNER, "live")

# -----------------------------------------------------------------------------
# Moves
# -----------------------------------------------------------------------------
move = {"game": G1, "ply": 0, "before": START, "move": "e2e4", "san": "e4", "after": AFTER_E4, "turn": "black",
        "legal": ["e7e5"]}
denied("players cannot write to games directly", f"update games set position = 'x' where id = '{G1}'", A)
denied("players cannot write moves directly",
       f"insert into moves (game_id, tournament_id, ply, move, position_after, clock_ms) values ('{G1}', '{TID}', 1, 'x', 'x', 1)", A)
denied("an unsigned move is refused", f"select ply from play_move('{json.dumps(move)}', 'nonsense')", A, "did not sign")
denied("Black cannot move for White", f"select ply from play_move({ruling('move', B, move)})", B, "not your move")
denied("a stranger cannot move in someone else's game", f"select ply from play_move({ruling('move', STRANGER, move)})", STRANGER, "not playing")
denied("a ruling on another position is refused",
       f"select ply from play_move({ruling('move', A, {**move, 'before': AFTER_E4})})", A, "moved on")
allowed("White plays e4", f"select ply from play_move({ruling('move', A, move)})", A, "1")
check("the move is recorded", value(f"select move || ' ' || san from moves where game_id = '{G1}' and ply = 1") == "e2e4 e4")
check("White's clock ran and gained the increment",
      0 < int(value(f"select white_ms from games where id = '{G1}'")) <= 302_000)
check("it is Black's turn, with Black's legal moves", value(f"select turn || ' ' || legal::text from games where id = '{G1}'") == 'black ["e7e5"]')
denied("the same ruling cannot be played twice", f"select ply from play_move({ruling('move', A, move)})", A)

# -----------------------------------------------------------------------------
# Draws, resignation, the clock
# -----------------------------------------------------------------------------
allowed("Black offers a draw", f"select draw_offer from offer_draw('{G1}')", B, "black")
denied("a stranger cannot accept it", f"select draw_offer from offer_draw('{G1}')", STRANGER, "no such game")
allowed("White declines", f"select coalesce(draw_offer, 'none') from decline_draw('{G1}')", A, "none")
allowed("declining with no offer answers with the game, not a row of nulls",
        f"select (id = '{G1}')::text || ' ' || ply from decline_draw('{G1}')", A, "true 1")
allowed("Black offers again", f"select draw_offer from offer_draw('{G1}')", B, "black")
allowed("White accepts by offering back", f"select result || ' ' || termination from offer_draw('{G1}')", A, "draw agreement")
check("the game is over and its clocks have stopped", value(f"select status from games where id = '{G1}'") == "finished")
denied("no moves after the end", f"select ply from play_move({ruling('move', A, move)})", A, "not in progress")

flag = {"game": G2, "ply": 0, "result": "black"}
denied("you cannot claim a flag with time on the clock", f"select status from claim_flag({ruling('flag', D, flag)})", D, "still time")
value(f"update games set turn_started_at = now() - interval '10 minutes' where id = '{G2}'")
denied("a flag claim cannot award the flagged side the game",
       f"select status from claim_flag({ruling('flag', D, {**flag, 'result': 'white'})})", D, "not a result")
denied("a stranger cannot claim a flag", f"select status from claim_flag({ruling('flag', STRANGER, flag)})", STRANGER, "no such game")
allowed("Black claims White's flag", f"select result || ' ' || termination from claim_flag({ruling('flag', D, flag)})", D, "black timeout")
check("White's clock reads zero", value(f"select white_ms from games where id = '{G2}'") == "0")
check("with both games over, the round closes", value(f"select status from rounds where id = '{RID}'") == "finished")

denied("a player cannot set results", f"select result from set_result('{G2}', 'white')", C)
allowed("the owner corrects a result", f"select result || ' ' || termination from set_result('{G2}', 'white')", OWNER, "white arbiter")

r2 = {"tournament": TID, "round": 2, "start": True, "games": [
    {"board": 1, "white": B, "black": C, "position": START, "turn": "white"},
    {"board": 2, "white": D, "black": A, "position": START, "turn": "white"},
]}
allowed("round two is published and started at once",
        f"select string_agg(status::text, ',') from publish_pairings({ruling('pairings', OWNER, r2)})", OWNER, "live,live")
G3 = value(f"select id from games where tournament_id = '{TID}' and board = 1 and white_id = '{B}'")
denied("you cannot resign someone else's game", f"select result from resign('{G3}')", A, "no such game")
allowed("Black resigns", f"select result || ' ' || termination from resign('{G3}')", C, "white resignation")

# -----------------------------------------------------------------------------
# Ratings
# -----------------------------------------------------------------------------
check("no-shows, first-move resignations and arbiter results leave ratings alone",
      value(f"select string_agg(chess_rating::text, ',') from profiles where id in ('{A}','{B}','{C}','{D}')") == "1500,1500,1500,1500")
G4 = value(f"select id from games where tournament_id = '{TID}' and white_id = '{D}' and round_id is not null and status = 'live'")
AFTER_E5 = "rnbqkbnr/pppp1ppp/8/4p3/4P3/8/PPPP1PPP/RNBQKBNR w KQkq - 0 2"
allowed("D opens", f"select ply from play_move({ruling('move', D, {'game': G4, 'ply': 0, 'before': START, 'move': 'e2e4', 'san': 'e4', 'after': AFTER_E4, 'turn': 'black'})})", D, "1")
allowed("A replies", f"select ply from play_move({ruling('move', A, {'game': G4, 'ply': 1, 'before': AFTER_E4, 'move': 'e7e5', 'san': 'e5', 'after': AFTER_E5, 'turn': 'white'})})", A, "2")
allowed("A resigns a game that was played", f"select result from resign('{G4}')", A, "white")
check("a rated win moves both players by K/2 at equal ratings",
      value(f"select (select chess_rating from profiles where id = '{D}') || ',' || (select chess_rating from profiles where id = '{A}')") == "1516,1484")
check("players cannot set their own rating", not sql(f"update profiles set chess_rating = 2800 where id = '{A}'", A)[0]
      or value(f"select chess_rating from profiles where id = '{A}'") == "1484")

# -----------------------------------------------------------------------------
# Who sees what
# -----------------------------------------------------------------------------
value(f"update tournaments set is_listed = false where id = '{TID}'")
allowed("a stranger sees no games of an unlisted event", "select count(*) from games", STRANGER, "0")
allowed("a visitor sees no games of an unlisted event", "select count(*) from games", ANON, "0")
allowed("a stranger holding an unlisted event's link sees its results, like its players",
        f"select count(*) from get_results('{TID}')", STRANGER, "4")
value(f"update tournaments set participants_visible = false where id = '{TID}'")
allowed("unless the organiser hides who has entered", f"select count(*) from get_results('{TID}')", STRANGER, "0")
allowed("which entrants still see past", f"select count(*) from get_results('{TID}')", C, "4")
value(f"update tournaments set participants_visible = true where id = '{TID}'")
allowed("an entrant sees every game", f"select count(*) from games where tournament_id = '{TID}'", C, "4")
allowed("an entrant sees the moves", f"select count(*) from moves where game_id = '{G1}'", C, "1")
value(f"update tournaments set is_listed = true, games_watchable = false where id = '{TID}'")
allowed("unwatchable games stay hidden from visitors", "select count(*) from games", ANON, "0")
allowed("but the scoreboard of a public event is public", f"select count(*) from get_results('{TID}')", ANON, "4")
value(f"update tournaments set games_watchable = true where id = '{TID}'")
allowed("watchable games are open to visitors", "select count(*) from games", ANON, "4")
allowed("and so are their moves", f"select count(*) from moves where game_id = '{G1}'", ANON, "1")
check("nobody can read the arena queue anonymously", not sql("select * from arena_queue", ANON)[0])

# -----------------------------------------------------------------------------
# Arena
# -----------------------------------------------------------------------------
AID = value(
    f"insert into tournaments (owner_id, title, game, variant, format, clock_base_s, starts_at, arena_minutes) "
    f"values ('{OWNER}', 'Arena Test', 'chess', 'standard', 'arena', 60, now(), 30) returning id"
)
value(f"update tournaments set status = 'registration' where id = '{AID}'")
value("insert into participants (tournament_id, user_id, status) values "
      + ",".join(f"('{AID}', '{u}', 'approved')" for u in (A, B, C)))
denied("the arena opens only when it goes live", f"select user_id from arena_join('{AID}')", A, "not open")
value(f"update tournaments set status = 'live' where id = '{AID}'")
denied("a stranger cannot join the arena", f"select user_id from arena_join('{AID}')", STRANGER, "no such tournament")
allowed("A joins the arena queue", f"select count(*) from arena_join('{AID}')", A, "1")
allowed("B joins too", f"select count(*) from arena_join('{AID}')", B, "1")
pair = {"tournament": AID, "round": None, "games": [{"white": A, "black": B, "position": START, "turn": "white"}]}
denied("C cannot pair A and B", f"select count(*) from publish_pairings({ruling('pairings', C, pair)})", C, "one of its two players")
denied("C cannot pair themselves with someone not waiting",
       f"select count(*) from publish_pairings({ruling('pairings', C, {**pair, 'games': [{'white': C, 'black': A, 'position': START}]})})",
       C, "no longer waiting")
allowed("B pairs with A: the game starts at once",
        f"select status from publish_pairings({ruling('pairings', B, pair)})", B, "live")
allowed("both have left the queue", f"select count(*) from arena_queue where tournament_id = '{AID}'", OWNER, "0")
denied("a pair cannot be made twice", f"select count(*) from publish_pairings({ruling('pairings', B, pair)})", B, "already in a game")
denied("you cannot queue while you are playing", f"select count(*) from arena_join('{AID}')", A, "finish your game")
value(f"update tournaments set started_at = now() - interval '31 minutes' where id = '{AID}'")
denied("the arena closes on time", f"select count(*) from arena_join('{AID}')", C, "not open")

sys.exit(1 if report() else 0)
