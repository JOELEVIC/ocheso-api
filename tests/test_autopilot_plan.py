"""
The autopilot's planning, without a database (core/autopilot.py, play/service.py).

plan_tournament() is a pure function of a sys-work snapshot and the database's
clock, so every branch of D4 is proven here: starting with enough players,
each short_field rule, pairing and finishing round by round, breaks, flags on
every tournament, and the arena's queue and closing. The executor is then run
against a fake system_call to show that races are outcomes, not errors, and
that leftovers roll over when the budget runs out.
"""

from datetime import datetime, timedelta, timezone

import pytest
from postgrest import APIError

import autopilot
from autopilot import (
    ArenaPair,
    Cancel,
    Finish,
    Flag,
    GoLive,
    Hold,
    PairRound,
    Postpone,
    Stalled,
    StartRound,
    plan_tournament,
)
from play import pairing, service
from play.standings import Result

NOW = datetime(2026, 10, 30, 19, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def players(n: int) -> list[dict]:
    """sys-work's `seeds`: approved, already in seeding order."""
    return [{"user_id": f"p{i}", "rating": 2000 - i * 10, "seed": None,
             "joined_at": iso(NOW - timedelta(days=1, minutes=n - i))} for i in range(1, n + 1)]


def tournament(**kw) -> dict:
    t = {"id": "t1", "slug": "weekly", "title": "Weekly", "status": "registration", "format": "swiss",
         "game": "chess", "variant": "standard", "starts_at": iso(NOW - timedelta(seconds=5)), "started_at": None,
         "rounds_count": 3, "arena_minutes": None, "tiebreaks": ["buchholz"], "autopilot": True,
         "min_players": 4, "short_field": "postpone", "postpone_min": 15, "max_postpones": 4, "round_break_s": 0}
    t.update(kw)
    return t


def snap(t=None, roster=None, results=None, rounds=None, queue=None, state=None, lease="L") -> dict:
    """A private.autopilot_snapshot."""
    seeds = roster if roster is not None else players(4)
    return {"lease": lease, "reasons": [], "tournament": t or tournament(), "seeds": seeds,
            "results": results or [], "rounds": rounds or [], "queue": queue or [], "state": state,
            "approved": len(seeds), "pending_invites": 0}


def work(*snaps, flags=None, series=None, mail=False) -> dict:
    """sys-work's reply."""
    return {"tournaments": list(snaps), "flags": flags or [], "series": series or [], "mail": mail,
            "server_now": iso(NOW)}


def game(gid, rnd, white, black, result=None, status=None, board=1, finished_at=None) -> dict:
    return {"game_id": gid, "round_number": rnd, "round_status": "finished" if result else "live", "board": board,
            "white_id": white, "black_id": black, "status": status or ("finished" if result else "live"),
            "result": result, "termination": None, "tiebreak_of": None,
            "finished_at": iso(finished_at) if finished_at else (iso(NOW - timedelta(minutes=1)) if result else None)}


# --- 1. registration past starts_at -------------------------------------------

def test_enough_players_go_live_and_round_one_starts_at_once():
    plan = plan_tournament(snap(t=tournament(round_break_s=120)), NOW)
    assert isinstance(plan[0], GoLive)
    assert isinstance(plan[1], PairRound) and plan[1].round == 1 and plan[1].start is True
    assert len(plan[1].pairs) == 2


def test_an_arena_goes_live_without_pairing():
    plan = plan_tournament(snap(t=tournament(format="arena", rounds_count=None, arena_minutes=60)), NOW)
    assert plan == [GoLive()]


def test_not_before_the_start_time():
    plan = plan_tournament(snap(t=tournament(starts_at=iso(NOW + timedelta(minutes=10)))), NOW)
    assert plan == [Hold(600)]


def test_min_players_never_below_two():
    t = tournament(min_players=None)
    assert isinstance(plan_tournament(snap(t=t, roster=players(2)), NOW)[0], GoLive)
    assert not isinstance(plan_tournament(snap(t=t, roster=players(1)), NOW)[0], GoLive)


def test_short_field_postpones():
    [p] = plan_tournament(snap(roster=players(3), state={"postponed": 1}), NOW)
    assert isinstance(p, Postpone) and p.minutes == 15 and "3 of 4" in p.note


def test_after_the_last_postponement_it_waits():
    [p] = plan_tournament(snap(roster=players(3), state={"postponed": 4}), NOW)
    assert isinstance(p, Hold) and p.seconds == 60 and "3 of 4" in p.note


def test_max_postpones_zero_means_wait_at_once():
    [p] = plan_tournament(snap(t=tournament(max_postpones=0), roster=players(1)), NOW)
    assert isinstance(p, Hold)


def test_short_field_wait_rechecks_every_minute():
    [p] = plan_tournament(snap(t=tournament(short_field="wait"), roster=players(2)), NOW)
    assert p == Hold(60, p.note)


def test_short_field_cancel_archives_with_a_note():
    [p] = plan_tournament(snap(t=tournament(short_field="cancel"), roster=players(2)), NOW)
    assert isinstance(p, Cancel) and "2 of 4" in p.note


# --- 2/3. live, round based ----------------------------------------------------

def live(**kw):
    return tournament(**{"status": "live", "started_at": iso(NOW - timedelta(minutes=30)), **kw})


def round_one_done():
    return [game("g1", 1, "p1", "p3", "white"), game("g2", 1, "p2", "p4", "draw", board=2)]


def test_all_games_done_pairs_the_next_round():
    rounds = [{"id": "r1", "number": 1, "status": "finished", "created_at": iso(NOW - timedelta(minutes=20))}]
    [p] = plan_tournament(snap(t=live(round_break_s=0), results=round_one_done(), rounds=rounds), NOW)
    assert isinstance(p, PairRound) and p.round == 2 and p.start is True


def test_with_a_break_the_round_is_published_then_started():
    rounds = [{"id": "r1", "number": 1, "status": "finished", "created_at": iso(NOW - timedelta(minutes=20))}]
    [p] = plan_tournament(snap(t=live(round_break_s=120), results=round_one_done(), rounds=rounds), NOW)
    assert isinstance(p, PairRound) and p.start is False


def test_a_pending_round_waits_out_its_break_then_starts():
    last_finish = NOW - timedelta(seconds=30)
    results = [game("g1", 1, "p1", "p3", "white", finished_at=last_finish),
               game("g3", 2, "p1", "p2", None, status="scheduled")]
    rounds = [{"id": "r1", "number": 1, "status": "finished", "created_at": iso(NOW - timedelta(minutes=20))},
              {"id": "r2", "number": 2, "status": "pending", "created_at": iso(NOW - timedelta(seconds=31))}]
    t = live(round_break_s=120)
    [p] = plan_tournament(snap(t=t, results=results, rounds=rounds), NOW)
    assert p == Hold(90)
    [p] = plan_tournament(snap(t=t, results=results, rounds=rounds), NOW + timedelta(seconds=91))
    assert p == StartRound("r2", 2)


def test_an_extended_break_holds_the_round():
    results = [game("g3", 2, "p1", "p2", None, status="scheduled")]
    rounds = [{"id": "r2", "number": 2, "status": "pending", "created_at": iso(NOW - timedelta(minutes=5))}]
    held = {"next_check_at": iso(NOW + timedelta(minutes=5))}
    [p] = plan_tournament(snap(t=live(round_break_s=60), results=results, rounds=rounds, state=held), NOW)
    assert p == Hold(300)


def test_a_game_still_on_means_nothing_to_do():
    results = [game("g1", 1, "p1", "p3", "white"), game("g2", 1, "p2", "p4", None, board=2)]
    rounds = [{"id": "r1", "number": 1, "status": "live", "created_at": iso(NOW - timedelta(minutes=20))}]
    assert plan_tournament(snap(t=live(), results=results, rounds=rounds), NOW) == []


def test_the_last_round_played_finishes_it():
    results = [game(f"g{r}{b}", r, a, c, "white", board=b)
               for r, pairs in ((1, [("p1", "p3"), ("p2", "p4")]), (2, [("p1", "p2"), ("p3", "p4")]),
                                (3, [("p1", "p4"), ("p2", "p3")]))
               for b, (a, c) in enumerate(pairs, 1)]
    rounds = [{"id": f"r{n}", "number": n, "status": "finished", "created_at": iso(NOW)} for n in (1, 2, 3)]
    [p] = plan_tournament(snap(t=live(rounds_count=3), results=results, rounds=rounds), NOW)
    assert isinstance(p, Finish) and p.reason == "every round has been played"


def test_a_complete_knockout_finishes():
    results = [game("g1", 1, "p1", "p2", "white")]
    rounds = [{"id": "r1", "number": 1, "status": "finished", "created_at": iso(NOW)}]
    t = live(format="knockout", rounds_count=None)
    [p] = plan_tournament(snap(t=t, roster=players(2), results=results, rounds=rounds), NOW)
    assert p == Finish("the knockout is complete")


def test_cannot_pair_stalls_and_retries_in_five_minutes():
    # A round robin of one player cannot be paired.
    t = live(format="round_robin", rounds_count=None)
    [p] = plan_tournament(snap(t=t, roster=players(1)), NOW)
    assert isinstance(p, Stalled) and p.seconds == 300


# --- 4. flags, on every tournament ---------------------------------------------

def flag(gid, ply, moves, game_type="chess", variant="standard"):
    return {"game": gid, "tournament": "t1", "ply": ply, "turn": "white" if ply % 2 == 0 else "black",
            "game_type": game_type, "variant": variant, "moves": moves}


def test_expired_clocks_are_ruled_by_the_referee():
    assert autopilot.plan_flags([flag("g9", 2, ["e2e4", "e7e5"])]) == [Flag("g9", 2, "black")]
    assert autopilot.plan_flags([flag("g8", 1, ["e2e4"])]) == [Flag("g8", 1, "white")]
    # Draughts, International: White to move at the start, out of time.
    assert autopilot.plan_flags([flag("d1", 0, [], "checkers", "international")]) == [Flag("d1", 0, "black")]


def test_a_flagged_game_holds_its_round_until_the_next_tick():
    results = [game("g1", 1, "p1", "p3", "white"), game("g2", 1, "p2", "p4", None, board=2)]
    plan = plan_tournament(snap(t=live(), results=results,
                                rounds=[{"id": "r1", "number": 1, "status": "live", "created_at": iso(NOW)}]), NOW)
    assert plan == []  # g2's flag is sys-work's `flags`; the round completes next tick


def test_without_autopilot_a_tournament_plans_nothing():
    assert plan_tournament(snap(t=tournament(autopilot=False)), NOW) == []


# --- 5. arena -------------------------------------------------------------------

def arena(**kw):
    return live(format="arena", rounds_count=None, arena_minutes=60, **kw)


def test_two_queued_are_paired():
    queue = [{"user_id": "p1", "since": iso(NOW - timedelta(seconds=20))},
             {"user_id": "p2", "since": iso(NOW - timedelta(seconds=10))}]
    [p] = plan_tournament(snap(t=arena(), queue=queue), NOW)
    assert isinstance(p, ArenaPair) and {p.pairing.white, p.pairing.black} == {"p1", "p2"}


def test_four_queued_make_two_games_and_nobody_twice():
    queue = [{"user_id": f"p{i}", "since": iso(NOW - timedelta(seconds=50 - i))} for i in range(1, 5)]
    plan = plan_tournament(snap(t=arena(), queue=queue), NOW)
    assert len(plan) == 2
    seated = [x for a in plan for x in (a.pairing.white, a.pairing.black)]
    assert sorted(seated) == ["p1", "p2", "p3", "p4"]


def test_someone_in_a_game_is_not_paired_again():
    queue = [{"user_id": "p1", "since": iso(NOW)}, {"user_id": "p2", "since": iso(NOW)}]
    results = [game("g1", None, "p2", "p3", None)]
    plan = plan_tournament(snap(t=arena(), queue=queue, results=results), NOW)
    assert all(not isinstance(a, ArenaPair) for a in plan)


def test_the_arena_finishes_when_the_window_closes_and_play_stops():
    t = arena(started_at=iso(NOW - timedelta(minutes=61)))
    assert plan_tournament(snap(t=t, results=[game("g1", None, "p1", "p2", "white")]), NOW) == \
        [Finish("the arena window has closed")]
    # ... but not while a game is still on.
    assert plan_tournament(snap(t=t, results=[game("g2", None, "p1", "p2", None)]), NOW) == []


# --- plan_round: the console's words, unchanged ---------------------------------

def seeds(n):
    return [pairing.Seed(f"p{i}", 2000 - i) for i in range(1, n + 1)]


def test_plan_round_waits_while_a_game_is_on():
    plan = service.plan_round({"format": "swiss", "rounds_count": 3}, seeds(4),
                              [Result(1, "p1", "p2", None, 1)])
    assert isinstance(plan, service.Wait)
    assert plan.reason.capitalize() + "." == "Games in this round are still being played."


def test_plan_round_done_wording():
    history = [Result(1, "p1", "p2", "white", 1)]
    plan = service.plan_round({"format": "swiss", "rounds_count": 1}, seeds(2), history)
    assert plan == service.Done("every round has been played")


def test_plan_round_round_robin_counts_rounds_from_the_first_field():
    plan = service.plan_round({"format": "round_robin", "rounds_count": None}, seeds(4), [])
    assert isinstance(plan, service.Pair) and plan.round == 1 and len(plan.pairs) == 2


def test_plan_round_refuses_an_arena():
    assert isinstance(service.plan_round({"format": "arena"}, seeds(4), []), service.CannotPair)


# --- the console summary ---------------------------------------------------------

def test_next_step_for_registration_and_rounds():
    t = tournament()
    assert autopilot.next_step(t, [], [], 3, NOW)["action"] == "start"
    t = live(round_break_s=120)
    rounds = [{"id": "r2", "number": 2, "status": "pending", "created_at": iso(NOW)}]
    step = autopilot.next_step(t, rounds, [], 4, NOW)
    assert step["action"] == "start_round" and step["at"] == iso(NOW + timedelta(seconds=120))


def test_timeline_marks_what_is_done():
    t = live(rounds_count=3, round_break_s=120)
    rounds = [{"id": "r1", "number": 1, "status": "finished"}, {"id": "r2", "number": 2, "status": "live"}]
    steps = autopilot.timeline(t, rounds, [], 4, NOW)
    by_key = {s["key"]: s["state"] for s in steps}
    assert by_key == {"entries": "done", "start": "done", "round:1": "done", "round:2": "current",
                      "round:3": "todo", "finish": "todo"}
    assert "2 min after the last game" in steps[3]["label"]


# --- the executor -----------------------------------------------------------------

class FakeDb:
    def __init__(self, work, refuse=None):
        self.work, self.refuse, self.calls = work, refuse or {}, []

    def __call__(self, kind, body):
        self.calls.append((kind, body))
        if kind == "sys-work":
            return self.work
        if kind in self.refuse:
            raise APIError({"code": self.refuse[kind], "message": "raced"})
        if kind == "sys-mail-batch":
            return []
        return {}


def test_one_tick_starts_pairs_and_releases():
    db = FakeDb(work(snap(t=tournament(round_break_s=0), lease="L1")))
    out = autopilot.run_tick(call=db)
    kinds = [k for k, _ in db.calls]
    assert kinds == ["sys-work", "sys-status", "sys-pairings", "sys-release"]
    status, pairings, release = (b for k, b in db.calls[1:])
    assert status == {"lease": "L1", "tournament": "t1", "status": "live"}
    assert pairings["lease"] == "L1" and pairings["round"] == 1 and pairings["start"] is True
    assert len(pairings["games"]) == 2 and all(g["position"].startswith("rnbqkbnr") for g in pairings["games"])
    # Going live makes "postponed / waiting" notes stale: cleared on release.
    assert release == {"lease": "L1", "tournament": "t1", "action": "golive,pair:1", "note": ""}
    assert out["tournaments"][0]["done"] == ["golive", "pair:1"]


def test_each_tournament_is_released_with_its_own_lease():
    db = FakeDb(work(snap(t=tournament(id="a"), lease="La"), snap(t=tournament(id="b", short_field="wait"),
                                                                    roster=players(2), lease="Lb")))
    autopilot.run_tick(call=db)
    released = {b["tournament"]: b for k, b in db.calls if k == "sys-release"}
    assert released["a"]["lease"] == "La" and released["b"]["lease"] == "Lb"
    assert released["b"]["retry_in"] == 60 and "2 of 4" in released["b"]["note"] and "action" not in released["b"]


@pytest.mark.parametrize("code", ["23514", "23505", "40001", "P0002"])
def test_a_race_is_an_outcome_and_stops_that_tournament(code):
    db = FakeDb(work(snap()), refuse={"sys-status": code})
    out = autopilot.run_tick(call=db)
    assert [k for k, _ in db.calls] == ["sys-work", "sys-status", "sys-release"]
    assert out["tournaments"][0]["raced"] == ["golive"] and out["tournaments"][0]["error"] is None
    assert "error" not in db.calls[-1][1]


def test_flags_run_for_every_tournament_and_a_raced_one_stops_nothing():
    calls = []

    def db(kind, body):
        calls.append((kind, body))
        if kind == "sys-work":
            return work(flags=[flag("a", 0, []), flag("b", 0, [])])
        if kind == "sys-flag" and body["game"] == "a":
            raise APIError({"code": "23514", "message": "there is still time on the clock"})
        return {}

    out = autopilot.run_tick(call=db)
    assert [b for k, b in calls if k == "sys-flag"] == [{"game": "a", "ply": 0, "result": "black"},
                                                        {"game": "b", "ply": 0, "result": "black"}]
    assert out["flags"] == {"flagged": 1, "raced": 1, "errors": 0}


def test_a_real_error_is_recorded_on_release():
    db = FakeDb(work(snap()), refuse={"sys-status": "XX000"})
    autopilot.run_tick(call=db)
    assert db.calls[-1][1]["error"].startswith("golive:")


def test_stalls_are_told_to_the_database_on_release():
    t = live(format="round_robin", rounds_count=None)
    db = FakeDb(work(snap(t=t, roster=players(1))))
    autopilot.run_tick(call=db)
    release = db.calls[-1][1]
    assert release["retry_in"] == 300 and release["stalled"] is True and "try again" in release["note"]
    assert "round robin needs" in release["error"]


def test_leftovers_roll_over_when_the_budget_is_spent():
    ticks = iter([0] * 3 + [50] * 20)  # began, left(a), plan(a); then b is over budget
    db = FakeDb(work(snap(t=tournament(id="a"), lease="La"), snap(t=tournament(id="b"), lease="Lb")))
    out = autopilot.run_tick(call=db, budget_s=40, clock=lambda: next(ticks))
    assert out["rolled_over"] == 1
    released = {b["tournament"]: b for k, b in db.calls if k == "sys-release"}
    assert set(released) == {"a", "b"} and released["b"] == {"lease": "Lb", "tournament": "b"}


def test_series_and_mail_run_once_per_tick(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "re_test")
    monkeypatch.setattr(settings, "MAIL_FROM", "Ocheso <invites@example.com>")
    sent = []

    def db(kind, body):
        sent.append((kind, body))
        if kind == "sys-work":
            return work(series=["s1", "s2"], mail=True)
        if kind == "sys-series":
            return {"created": {"slug": f"weekly-{body['series']}"}}
        if kind == "sys-mail-batch":
            return {"invites": [{"id": "i1", "to": "a@b.co", "token": "0" * 32, "language": "en",
                                 "tournament": {"slug": "w", "title": "Weekly", "starts_at": iso(NOW)}}],
                    "outbox": [{"id": 7, "kind": "postponed", "to": "o@b.co", "data": {"slug": "w"}}]}
        return {}

    def resend(batch):
        return [{"id": batch[0]["id"], "ok": True}, {"id": batch[1]["id"], "ok": False, "error": "resend 503"}]

    out = autopilot.run_tick(call=db, send_mail=resend)
    assert [k for k, _ in sent] == ["sys-work", "sys-series", "sys-series", "sys-mail-batch", "sys-mail-done"]
    assert [b for k, b in sent if k == "sys-series"] == [{"series": "s1"}, {"series": "s2"}]
    # The transient failure is left to retry when its hold lapses.
    assert sent[-1][1] == {"invites": [{"id": "i1", "ok": True}], "outbox": []}
    assert out["mail"]["sent"] == 1 and out["mail"]["retry"] == 1 and out["series"] == ["weekly-s1", "weekly-s2"]


def test_mail_off_leaves_the_outbox_alone(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "")
    db = FakeDb(work(mail=True))
    out = autopilot.run_tick(call=db)
    assert [k for k, _ in db.calls] == ["sys-work"] and out["mail"]["on"] is False
    # ...and tells the database so, which then stops kicking a tick every
    # 10 s for mail alone (private.mail_kick_ok).
    assert db.calls[0][1] == {"limit": autopilot.LEASE_LIMIT, "mail_on": False}


def test_the_database_hears_when_mail_is_on(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "RESEND_API_KEY", "re_test")
    monkeypatch.setattr(settings, "MAIL_FROM", "Ocheso <invites@example.com>")
    db = FakeDb(work())
    autopilot.run_tick(call=db)
    assert db.calls[0] == ("sys-work", {"limit": autopilot.LEASE_LIMIT, "mail_on": True})


def test_a_series_that_cannot_make_its_instance_is_reported_not_fatal():
    def db(kind, body):
        if kind == "sys-work":
            return work(series=["bad", "good"])
        if kind == "sys-series" and body["series"] == "bad":
            return {"created": None, "error": "the community plan allows 64 players per event"}
        if kind == "sys-series":
            return {"created": {"slug": "weekly-2"}}
        return {}

    out = autopilot.run_tick(call=db)
    assert out["series"] == ["weekly-2"]
    assert out["series_errors"] == [{"series": "bad", "error": "the community plan allows 64 players per event"}]
