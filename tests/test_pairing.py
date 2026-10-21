"""
Pairings, tested by playing whole tournaments with random results and checking
what an arbiter would check: nobody meets twice, colours stay balanced, the
bye moves around, and the bracket ends with one winner.
"""

from __future__ import annotations

import itertools
import random
from collections import Counter

import pytest

from play.pairing import (
    CannotPair,
    Seed,
    arena_pick,
    knockout,
    knockout_champion,
    round_robin,
    round_robin_rounds,
    swiss,
)
from play.standings import Result, arena, table


def field(n: int) -> list[Seed]:
    return [Seed(f"p{i:02d}", 2000 - i * 25) for i in range(n)]


def play(pairings, round_no: int, rng: random.Random, draws: float = 0.25) -> list[Result]:
    out = []
    for p in pairings:
        if p.black is None:
            out.append(Result(round_no, p.white, None, "white", p.board, game_id=f"g{round_no}.{p.board}.bye"))
            continue
        x = rng.random()
        res = "draw" if x < draws else "white" if x < (1 + draws) / 2 else "black"
        gid = f"g{round_no}.{p.board}.{rng.random():.6f}"
        out.append(Result(round_no, p.white, p.black, res, p.board, tiebreak_of=p.tiebreak_of, game_id=gid))
    return out


def colours(history: list[Result]) -> dict[str, list[str]]:
    c: dict[str, list[str]] = {}
    for g in sorted(history, key=lambda g: g.round or 0):
        if g.black is None:
            continue
        c.setdefault(g.white, []).append("W")
        c.setdefault(g.black, []).append("B")
    return c


# -----------------------------------------------------------------------------
@pytest.mark.parametrize("n", [4, 5, 6, 7, 8, 10, 11])
def test_round_robin_everyone_meets_everyone_once(n):
    players = field(n)
    history: list[Result] = []
    rng = random.Random(n)
    for r in range(1, round_robin_rounds(n) + 1):
        history += play(round_robin(players, r), r, rng)
    met = Counter(frozenset((g.white, g.black)) for g in history if g.black)
    assert set(met) == {frozenset(pair) for pair in itertools.combinations([p.id for p in players], 2)}
    assert set(met.values()) == {1}
    for pid, cs in colours(history).items():
        assert abs(cs.count("W") - cs.count("B")) <= 1 + (n % 2), (pid, cs)
    if n % 2:
        byes = Counter(g.white for g in history if g.black is None)
        assert set(byes.values()) == {1} and len(byes) == n


def test_round_robin_refuses_a_round_that_does_not_exist():
    with pytest.raises(CannotPair):
        round_robin(field(4), 4)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize("n,seed", [(2, 1), (5, 2), (6, 3), (8, 4), (13, 5), (16, 6)])
def test_knockout_runs_to_one_champion(n, seed):
    players = field(n)
    rng = random.Random(seed)
    history: list[Result] = []
    rounds_seen = set()
    for _ in range(200):
        try:
            rnd, pairs = knockout(players, history)
        except CannotPair as e:
            assert "complete" in str(e)
            break
        rounds_seen.add(rnd)
        history += play(pairs, rnd, rng, draws=0.4)
    champion = knockout_champion(history)
    assert champion in {p.id for p in players}
    size = 1 << (n - 1).bit_length()
    assert len(rounds_seen) == max(1, size.bit_length() - 1)


def test_knockout_top_seeds_get_the_byes_and_meet_last():
    rnd, pairs = knockout(field(6), [])
    assert rnd == 1
    byes = [p.white for p in pairs if p.black is None]
    assert byes == ["p00", "p01"]
    # Seeds 1 and 2 are in opposite halves of the draw.
    boards = {p.white: p.board for p in pairs} | {p.black: p.board for p in pairs if p.black}
    assert (boards["p00"] <= 2) != (boards["p01"] <= 2)


def test_knockout_draw_gets_a_tiebreak_with_colours_reversed():
    players = field(2)
    _, [first] = knockout(players, [])
    drawn = Result(1, first.white, first.black, "draw", first.board, game_id="g1")
    rnd, [again] = knockout(players, [drawn])
    assert rnd == 1 and (again.white, again.black) == (first.black, first.white) and again.tiebreak_of == "g1"


# -----------------------------------------------------------------------------
@pytest.mark.parametrize("n,rounds,seed", [(4, 3, 1), (7, 5, 2), (9, 5, 3), (12, 6, 4), (16, 7, 5), (25, 7, 6)])
def test_swiss_pairs_cleanly(n, rounds, seed):
    players = field(n)
    rng = random.Random(seed)
    history: list[Result] = []
    for r in range(1, rounds + 1):
        pairs = swiss(players, history, r)
        ids = [p.white for p in pairs] + [p.black for p in pairs if p.black]
        assert sorted(ids) == sorted(p.id for p in players), "everyone is paired exactly once"
        history += play(pairs, r, rng)

    games = [g for g in history if g.black]
    met = Counter(frozenset((g.white, g.black)) for g in games)
    if rounds < n:
        assert max(met.values()) == 1, "nobody meets twice"
    byes = Counter(g.white for g in history if g.black is None)
    assert all(v == 1 for v in byes.values()), "the bye moves around"
    for pid, cs in colours(history).items():
        assert abs(cs.count("W") - cs.count("B")) <= 2, (pid, cs)
        assert "WWW" not in "".join(cs) and "BBB" not in "".join(cs), (pid, cs)


def test_swiss_round_one_is_top_half_against_bottom_half():
    pairs = swiss(field(8), [], 1)
    assert {(p.white, p.black) for p in pairs} == {
        ("p00", "p04"), ("p05", "p01"), ("p02", "p06"), ("p07", "p03"),
    }


def test_swiss_pairs_leaders_together():
    players = field(8)
    # p00 and p01 won round one, everyone else lost or drew.
    r1 = [
        Result(1, "p00", "p04", "white"), Result(1, "p05", "p01", "black"),
        Result(1, "p02", "p06", "draw"), Result(1, "p07", "p03", "draw"),
    ]
    pairs = swiss(players, r1, 2)
    top = pairs[0]
    assert {top.white, top.black} == {"p00", "p01"} and top.board == 1


# -----------------------------------------------------------------------------
def test_standings_with_tiebreaks():
    players = {"a": 2000, "b": 1900, "c": 1800, "d": 1700}
    results = [
        Result(1, "a", "b", "white"), Result(1, "c", "d", "draw"),
        Result(2, "a", "c", "draw"), Result(2, "d", "b", "black"),
    ]
    lines = table(players, results, ["buchholz", "sonneborn_berger"])
    by = {l.player: l for l in lines}
    # b and c are level on points and on Buchholz (opponents a + d = 2.0 each).
    assert by["b"].tiebreaks["buchholz"] == by["c"].tiebreaks["buchholz"] == 2.0
    # Sonneborn-Berger separates them: b beat d (0.5); c drew a and d (0.75 + 0.25).
    assert by["b"].tiebreaks["sonneborn_berger"] == 0.5
    assert by["c"].tiebreaks["sonneborn_berger"] == 1.0
    assert [(l.player, l.points) for l in lines] == [("a", 1.5), ("c", 1.0), ("b", 1.0), ("d", 0.5)]


def test_arena_streaks_double_the_score():
    players = {"a": 1500, "b": 1500}
    games = [Result(None, "a", "b", "white"), Result(None, "b", "a", "black"), Result(None, "a", "b", "white")]
    lines = {l.player: l for l in arena(players, games)}
    # 2 + 2, then the streak doubles the third win to 4.
    assert lines["a"].points == 8 and lines["b"].points == 0


def test_arena_pick_avoids_an_immediate_rematch():
    waiting = [Seed("me", 1500), Seed("last", 1500), Seed("other", 1400)]
    history = [Result(None, "me", "last", "draw")]
    p = arena_pick("me", waiting, {"me": 1, "last": 1, "other": 0}, history)
    assert {p.white, p.black} == {"me", "other"}
