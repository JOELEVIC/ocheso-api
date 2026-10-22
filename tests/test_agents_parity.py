"""
The Python brain decides exactly as the TypeScript brain it was ported from.

agents/golden/v2.json.gz was exported from the TypeScript kits at the old
monorepo's last commit (0d63683), after confirming that commit still matched
CCA's frozen house-core goldens. Every section here is compared value for value;
floats to one part in a billion, because JavaScript's and Python's maths
libraries may differ in the last bit while a real change moves numbers far
more. Board facts and chess.js's move order are compared exactly.
"""

from __future__ import annotations

import gzip
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agents import etiquette as E
from agents.chess import board as B
from agents.chess.analysis import cp_at, from_snapshot, pct_of_cp, ranked
from agents.chess.archetypes import ARCHETYPES, LINES, persona_for, typical_persona
from agents.chess.brain import budget_for
from agents.chess.decide import character, decide
from agents.chess.gauge import gauge, solution_depth
from agents.chess.intuition import book_move
from agents.chess.maia import maia_history, maia_input, maia_policy, policy_moves
from agents.chess.persona import TRAITS, persona
from agents.chess.priors import PRIORS_V0, PRIORS_V1, THINK_V1
from agents.mood import after_game, after_own_move, start_game
from agents.persona import parse_cadence
from agents.rng import rng_from
from agents.schedule import local_time, online_at, sessions_on
from agents.think_time import measured_ms, think_time, typical_ms

GOLDEN = Path(__file__).parent.parent / "agents" / "golden"
G = json.load(gzip.open(GOLDEN / "v2.json.gz"))
FIXTURES = json.loads((GOLDEN / "fixtures.json").read_text())["positions"]
RATINGS = [400, 1000, 1600, 2200]
SEEDS = ["a", "b", "c"]
PRIOR_SETS = [("v0", PRIORS_V0), ("v1", PRIORS_V1)]


def same(got, exp, path="") -> list[str]:
    """Differences between two JSON-like values, floats to 1e-9."""
    if isinstance(exp, bool) or isinstance(got, bool):
        return [] if got == exp else [f"{path}: {got!r} != {exp!r}"]
    if isinstance(exp, (int, float)) and isinstance(got, (int, float)):
        return [] if math.isclose(got, exp, rel_tol=1e-9, abs_tol=1e-9) else [f"{path}: {got!r} != {exp!r}"]
    if isinstance(exp, dict) and isinstance(got, dict):
        out = []
        for k in set(exp) | set(got):
            if k not in got and exp.get(k) is None:
                continue
            if k not in exp and got.get(k) is None:
                continue
            out += same(got.get(k), exp.get(k), f"{path}.{k}")
        return out
    if isinstance(exp, list) and isinstance(got, list):
        if len(exp) != len(got):
            return [f"{path}: length {len(got)} != {len(exp)}"]
        out = []
        for i, (g, e) in enumerate(zip(got, exp)):
            out += same(g, e, f"{path}[{i}]")
        return out
    return [] if got == exp else [f"{path}: {got!r} != {exp!r}"]


def check(got, exp, what):
    diffs = same(got, exp, what)
    assert not diffs, f"{len(diffs)} differences, first: {diffs[:5]}"


# -----------------------------------------------------------------------------
def test_personas_parse_as_typescript_does():
    check(persona({"rating": 1200}), G["personas"]["default"], "default")
    for a in ARCHETYPES:
        for rating in (300, 1200, 2500):
            check(persona_for(a["id"], rating), G["personas"][f"{a['id']}|{rating}"], f"{a['id']}|{rating}")
    for rating in (250, 800, 1900):
        check(typical_persona(rating), G["personas"][f"typical|{rating}"], f"typical|{rating}")
    check(TRAITS, G["traits"], "traits")
    check(LINES, G["lines"], "lines")
    check([{k: v for k, v in a.items()} for a in ARCHETYPES], G["archetypes"], "archetypes")


def test_priors_and_budgets():
    for pv, p in PRIOR_SETS:
        exp = G["priors"][pv]
        at = lambda f: [f(r) for r in [100, 300, 500, 700, 800, 900, 1200, 1500, 1800, 2100, 2400, 2700]]  # noqa: E731
        got = {
            "version": p.version, "visionDepth": at(p.vision_depth), "lapse": at(p.lapse), "temperature": at(p.temperature),
            "policyWeight": at(p.policy_weight), "perceptionNoise": at(p.perception_noise), "timeUsage": at(p.time_usage),
            "thinkSigma": p.think_sigma, "expectedMoves": p.expected_moves, "maiaFloor": p.maia_floor, "maiaCeiling": p.maia_ceiling,
            "budgets": [budget_for(r, p) for r in (400, 1200, 2000)],
        }
        check(got, exp, pv)
    check(THINK_V1, G["thinkV1"], "thinkV1")


def test_think_times():
    shapes = [
        ("plain", {}), ("first", {"ownMove": 0}), ("book", {"ownMove": 3, "book": True}), ("only", {"onlyMove": True}),
        ("recapture", {"recapture": True}), ("check", {"inCheck": True}), ("sharp", {"complexity": 0.9, "criticality": 0.8}),
        ("low-clock", {"clockMs": 9_000}), ("losing", {"evalPct": 12}), ("winning", {"evalPct": 88}),
    ]
    n = 0
    for a in ARCHETYPES:
        for rating in RATINGS:
            p = persona_for(a["id"], rating)
            for c in ("1+0", "3+2", "5+0", "10+5", "30+0", "7+3"):
                cad = parse_cadence(c)
                for name, over in shapes:
                    inp = {"rating": rating, "cadence": cad, "ownMove": 18, "clockMs": cad["baseSec"] * 600, "complexity": 0.4,
                           "criticality": 0.3, "onlyMove": False, "recapture": False, "inCheck": False, "book": False, "evalPct": 50, **over}
                    for pv, priors in PRIOR_SETS:
                        rng = rng_from(f"think/{a['id']}/{rating}/{c}/{name}/{pv}")
                        mood = start_game(p, 2, rating, rng.fork("mood"))
                        got = {"mood": mood, "result": think_time(inp, p, mood, priors, rng),
                               "measured": measured_ms(inp, priors), "typical": typical_ms(inp, priors)}
                        key = f"{a['id']}|{rating}|{c}|{name}|{pv}"
                        check(got, G["thinkTimes"][key], key)
                        n += 1
    assert n == len(G["thinkTimes"])


def test_schedules_and_local_time():
    day0 = datetime(2026, 10, 5, tzinfo=timezone.utc).timestamp()
    for a in ARCHETYPES:
        p = persona_for(a["id"], 1200)
        for d in range(14):
            at = datetime.fromtimestamp(day0 + d * 86_400, timezone.utc)
            date = at.strftime("%Y-%m-%d")
            weekday = (at.weekday() + 1) % 7
            check(sessions_on(p, f"seed-{a['id']}", date, weekday), G["schedules"][f"{a['id']}|{date}"], f"{a['id']}|{date}")
        got = [online_at(p, f"seed-{a['id']}", datetime.fromtimestamp(day0 + i * 5 * 3600 + 17 * 60, timezone.utc)) for i in range(34)]
        check(got, G["schedules"][f"{a['id']}|onlineAt"], f"{a['id']}|onlineAt")
    for iso, tz, exp in G["localTime"]:
        check(local_time(datetime.fromisoformat(iso.replace("Z", "+00:00")), tz), exp, f"{iso} {tz}")


def test_manners():
    for a in ARCHETYPES:
        for rating in (500, 1500, 2300):
            p = persona_for(a["id"], rating)
            rows = []
            for i in range(12):
                rng = rng_from(f"manners/{a['id']}/{rating}/{i}")
                mood = start_game(p, i % 4, rating + 100 * (i % 3) - 100, rng.fork("mood"))
                moved = after_own_move(mood, p, i * 3, 50 - i * 3)
                rows.append([
                    mood, moved, after_game(moved, p, i % 2 == 0), E.greeting(p, rng), E.oops(p, i * 4, rng),
                    E.compliment(p, i * 2, i / 12, rng), E.farewell(p, ("win", "loss", "draw")[i % 3], moved, rng),
                    E.should_resign(p, rating, i, i, rng),
                    E.should_offer_draw(p, 48 + (i % 5), 0.5 + i / 24, 20 + i * 2, i % 3, rating + 150, rng),
                    E.accept_draw(p, 30 + i * 3, rating + 100, moved, rng),
                    E.rematch(p, ("win", "loss", "draw")[i % 3], moved, rng),
                    book_move(p, ["e2e4", "e7e5", "g1f3", "b8c6"][: i % 5], (i % 5) // 2, rng),
                ])
            check(rows, G["manners"][f"{a['id']}|{rating}"], f"{a['id']}|{rating}")


def test_analysis_reading():
    for fx, exp in zip(FIXTURES, G["analysis"]):
        a = from_snapshot(fx["analysis"])
        facts = B.move_facts(B.Position(a.fen, a.history))
        r = ranked(a)
        got = {
            "name": fx["name"],
            "ranked": r,
            "character": character(a, facts),
            "cpAt": [[e.move, [cp_at(e, d) for d in (1, 2, 3, 5, 8, 12, 30)]] for e in list(a.moves.values())[:6]],
            "solutionDepth": solution_depth(a, r[0]["move"]) if r else None,
        }
        check(got, exp, fx["name"])
    check([[cp, pct_of_cp(cp)] for cp, _ in G["winpct"]], G["winpct"], "winpct")


def test_decisions():
    n = 0
    for fx in FIXTURES:
        a = from_snapshot(fx["analysis"])
        for arch in ARCHETYPES:
            for rating in RATINGS:
                for pv, priors in PRIOR_SETS:
                    for seed in SEEDS:
                        p = persona_for(arch["id"], rating)
                        rng = rng_from(f"{fx['name']}/{arch['id']}/{rating}/{seed}")
                        mood = start_game(p, 1, rating + 50, rng.fork("mood"))
                        d = decide(a, persona=p, priors=priors, mood=mood, rng=rng, own_move=11, clock_ms=300_000,
                                   cadence={"baseSec": 600, "incSec": 0}, from_start=False)
                        key = f"{fx['name']}|{arch['id']}|{rating}|{pv}|{seed}"
                        check({"mood": mood, "decision": d}, G["decisions"][key], key)
                        n += 1
    assert n == len(G["decisions"]) == 2016


def test_book_lines_from_the_start():
    for arch in ARCHETYPES:
        for rating in (500, 1500):
            p = persona_for(arch["id"], rating)
            at = B.Position("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", [])
            line = []
            for ply in range(10):
                a = from_snapshot({"fen": at.fen, "history": at.history, "moves": [], "policy": [], "maxDepth": 0})
                rng = rng_from(f"book/{arch['id']}/{rating}/{ply}")
                mood = start_game(p, 0, rating, rng.fork("mood"))
                d = decide(a, persona=p, priors=PRIORS_V1, mood=mood, rng=rng, own_move=ply // 2, clock_ms=600_000,
                           cadence={"baseSec": 600, "incSec": 5}, from_start=True)
                line.append({"move": d["move"], "book": d["book"], "thinkMs": d["thinkMs"], "tags": d["tags"]})
                at = B.play(at, d["move"])
            check(line, G["book"][f"{arch['id']}|{rating}"], f"{arch['id']}|{rating}")


def test_gauges():
    for fx in FIXTURES:
        a = from_snapshot(fx["analysis"])
        for pv, priors in PRIOR_SETS:
            check(gauge(a, samples=40, seed=fx["name"], priors=priors), G["gauges"][f"{fx['name']}|{pv}"], f"{fx['name']}|{pv}")


def test_maia_encoding():
    assert policy_moves() == G["maia"]["policyMoves"]
    for case in G["maia"]["inputs"]:
        pos = B.Position(case["start"] or "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", [])
        for mv in case["line"]:
            pos = B.play(pos, mv)
        assert pos.fen == case["fen"]
        h = maia_history(case["start"], case["line"], pos.fen)
        check(h, case["history"], f"{case['fen']} history")
        planes = maia_input(h["fens"], h["fromStandardStart"])
        check([[i, v] for i, v in enumerate(planes) if v != 0], case["nonzero"], f"{case['fen']} planes")
        logits = [math.sin(i * 0.37) * 3 for i in range(1858)]
        check(maia_policy(logits, pos.fen), case["policy"], f"{case['fen']} policy")
        check(maia_policy(logits, pos.fen, 0.5), case["policyHot"], f"{case['fen']} policy hot")


@pytest.mark.slow
def test_calibration_replay_is_unchanged():
    from agents.chess.replay import replay

    r = replay(8, priors=PRIORS_V1)
    exp = G["replay"]
    assert {k: r[k] for k in ("positions", "samples", "top1", "logLik", "blunderGap")} == {
        k: exp[k] for k in ("positions", "samples", "top1", "logLik", "blunderGap")
    }
    mismatched = [i for i, (g, e) in enumerate(zip(r["moves"], exp["moves"])) if g != e]
    assert not mismatched, f"{len(mismatched)} positions decided differently, first {mismatched[:5]}"
    # Floors, so a re-made golden can't quietly accept a worse brain.
    assert r["top1"] >= 0.42 and r["blunderGap"] <= 0.02


@pytest.mark.slow
def test_native_calibration_replay():
    """v2 on the positions as the runtime's engines see them (agents/calibration.py).
    Exact, so any change to how the brain decides shows here; v1's scores on the
    same analyses are the floor (top-1 at 8 samples is too noisy to floor: v2 is
    48.4% to v1's 47.3% at 32)."""
    from pathlib import Path

    from agents.chess.priors import PRIORS
    from agents.chess.replay import replay, rows

    r = replay(8, priors=PRIORS, positions=rows(Path(__file__).parent.parent / "agents/golden/native-heldout.jsonl.gz"))
    assert {k: r[k] for k in ("positions", "top1", "logLik", "blunderGap")} == {
        "positions": 1006, "top1": 0.4344, "logLik": -2.2914, "blunderGap": 0.0236,
    }
    assert r["logLik"] >= -2.3003 and r["blunderGap"] <= 0.026
