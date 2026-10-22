"""
Seat dispatch and challenge answers, held exactly to the TypeScript kit they
were ported from (agents/golden/dispatch.json.gz, exported from @ocheso/agents).
"""

import gzip
import json
import math
from pathlib import Path

from agents.dispatch import (
    DEFAULT_DISPATCH,
    answer_challenge,
    answer_friend_request,
    decide_seat,
    rating_window,
    wait_for,
)
from agents.rng import rng_from

G = json.loads(gzip.open(Path(__file__).parent.parent / "agents/golden/dispatch.json.gz").read(),
               parse_constant=lambda c: math.inf)


def _inf(v):
    return math.inf if v == "Infinity" else v


def test_defaults_and_windows():
    assert G["defaults"] == DEFAULT_DISPATCH
    for w in G["windows"]:
        assert rating_window(w["ageMs"]) == _inf(w["window"])
    for w in G["waits"]:
        assert wait_for(w["id"], DEFAULT_DISPATCH) == w["ms"]


def test_seats_are_decided_as_typescript_does():
    takes = 0
    for case in G["seats"]:
        agents = [{**a, "persona": G["personas"][a["id"]]} for a in case["agents"]]
        got = decide_seat(case["seek"], agents, case["now"], case["settings"], rng_from(f"seat/{case['seek']['id']}"))
        assert got == case["decision"], case["seek"]["id"]
        takes += got["action"] == "take"
    assert takes > 20  # the cases reach every branch, taking included


def test_challenges_are_answered_as_typescript_does():
    actions = set()
    for case in G["challenges"]:
        c, a = case["challenge"], case["agent"]
        m = {**a, "persona": G["personas"][a["id"]]}
        rng = rng_from(f"challenge/{c['id']}/{str(a['online']).lower()}/{str(a['idle']).lower()}/{str(c['isPosition']).lower()}")
        got = answer_challenge(c, m, DEFAULT_DISPATCH, rng)
        assert got == case["answer"], c["id"]
        actions.add(got["action"])
    assert actions == {"accept", "decline", "ignore"}


def test_friend_requests():
    p = G["personas"]["social-1300"]
    a = answer_friend_request(p, "x")
    assert a == answer_friend_request(p, "x") and 60_000 <= a["afterMs"] <= 1_200_000
    accepted = sum(answer_friend_request(p, f"s{i}")["accept"] for i in range(200))
    assert 150 < accepted < 200  # warm personas mostly accept


def test_always_around_means_the_whole_day():
    from datetime import datetime, timezone

    from agents.schedule import online_at, sessions_on

    p = json.loads(json.dumps(G["personas"]["typical-1300"]))
    p["life"]["weekly"] = [{"days": [0, 1, 2, 3, 4, 5, 6], "from": "00:00", "to": "23:59", "presence": 1}]
    assert sessions_on(p, "a", "2026-10-22", 4) == [{"from": 0, "to": 1440}]
    for hour in (0, 7, 13, 19, 23):
        assert online_at(p, "a", datetime(2026, 10, 22, hour, 30, tzinfo=timezone.utc))["online"]
