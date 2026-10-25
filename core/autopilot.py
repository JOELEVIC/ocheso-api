"""
The autopilot: tournaments that run themselves (docs/OCHESO_PLATFORMS.md A5, C8, D4).

Every 10 seconds pg_cron runs private.autopilot_kick(), which - when something
is due - posts a signed tick to POST /v1/internal/tick (routers/internal.py).
The tick asks `sys-work` (db/platforms.sql) for up to ten due tournaments,
each leased to this tick and described by a snapshot, plus every live game out
of time, the series that need an instance and whether mail is waiting. It
plans each tournament here, acts through `system_call` (db.py), and releases
each lease with what it did.

Planning and acting are separate on purpose. `plan_tournament(snapshot, now)`
is a pure function of what the database said - no I/O, no clock of its own -
so tests/test_autopilot_plan.py proves every branch without a database, and
the executor below is a dumb loop that turns actions into `sys-*` calls.

Racing a person is normal: an organiser presses "Start now" while the tick is
starting the same event. The database refuses the second of the two (every
`sys-*` call re-checks the lease and the state), and a 409 or 404 from a race
is an outcome here, not an error: the tournament is replanned on the next tick
from whatever is true then.

The plan follows D4's order: flags first (they apply to EVERY tournament, with
autopilot on or not - a behaviour change, see README.md 5; sys-work lists
them apart from the leased snapshots), then the step each tournament's state
calls for:
  1. registration past starts_at  - start with enough players, else short_field
  2. live and round-based, all games done - plan_round: pair, finish or stall
  3. a published round whose break is over - start its clocks
  5. arena - pair whoever is queued; finish once the window closes and play stops
Series (6) and mail (7) are per tick, not per tournament; release (8) closes it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Union

from postgrest import APIError

from config import settings
from db import fail, system_call, ts
from play import pairing, rules, service

log = logging.getLogger("ocheso.autopilot")

BUDGET_S = 40.0          # of the function's 60: room to release and answer
LEASE_LIMIT = 10
STALL_RETRY_S = 300      # CannotPair: look again in five minutes
WAIT_RECHECK_S = 60      # short_field = wait
MAIL_BATCH = 50
MAIL_MIN_LEFT_S = 8.0    # don't start a Resend call the budget can't finish


def _span(seconds: int) -> str:
    return f"{seconds // 60} min" if seconds % 60 == 0 else f"{seconds} s"


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class Flag:
    game: str
    ply: int
    result: str


@dataclass(frozen=True)
class GoLive:
    pass


@dataclass(frozen=True)
class PairRound:
    round: int
    pairs: list[pairing.Pairing]
    start: bool


@dataclass(frozen=True)
class StartRound:
    round_id: str
    number: int


@dataclass(frozen=True)
class ArenaPair:
    pairing: pairing.Pairing


@dataclass(frozen=True)
class Finish:
    reason: str


@dataclass(frozen=True)
class Postpone:
    minutes: int
    note: str


@dataclass(frozen=True)
class Cancel:
    note: str


@dataclass(frozen=True)
class Hold:
    """Nothing to do yet: look again in `seconds` (and say why, if `note`)."""

    seconds: int
    note: Optional[str] = None


@dataclass(frozen=True)
class Stalled:
    reason: str
    seconds: int = STALL_RETRY_S


Action = Union[Flag, GoLive, PairRound, StartRound, ArenaPair, Finish, Postpone, Cancel, Hold, Stalled]


# -----------------------------------------------------------------------------
# Planning (pure)
# -----------------------------------------------------------------------------
def plan_flags(flags: list[dict]) -> list[Flag]:
    """sys-work's `flags`: every live game whose side to move is out of time,
    in any tournament - {game, tournament, ply, turn, game_type, variant,
    moves}. The referee rules on the result: out of time loses, unless the
    opponent could never have won."""
    out = []
    for f in flags or []:
        game = f.get("game_type") or "chess"
        variant = "standard" if game == "chess" else (f.get("variant") or "international")
        out.append(Flag(f["game"], int(f["ply"]), rules.flag_result(game, variant, list(f.get("moves") or []))))
    return out


def plan_tournament(snap: dict, now: datetime) -> list[Action]:
    """What to do for one leased tournament, from its sys-work snapshot
    (private.autopilot_snapshot):

        {lease, reasons, tournament: {...tournaments row},
         state:   {postponed, next_check_at, hold_until, ...} | null,
         seeds:   [{user_id, rating, seed, joined_at}],     # approved, seeded
         results: [{game_id, round_number, round_status, board, white_id,
                    black_id, status, result, termination, tiebreak_of,
                    finished_at}],
         rounds:  [{id, number, status, created_at, started_at, finished_at}],
         queue:   [{user_id, since}],                        # arena
         approved, pending_invites}
    """
    t = snap["tournament"]
    if not t.get("autopilot"):
        return []
    if t["status"] == "registration":
        return _plan_start(snap, now)
    if t["status"] != "live":
        return []
    if t["format"] == "arena":
        return _plan_arena(snap, now)
    return _plan_rounds(snap, now)


def seeds_of(snap: dict) -> list[pairing.Seed]:
    """The field in seeding order: the database already sorted `seeds` the way
    play/service.py seeds_from_roster sorts a roster (seed, rating, arrival)."""
    if "seeds" in snap:
        return [pairing.Seed(x["user_id"], x.get("rating") or 0) for x in snap.get("seeds") or []]
    return service.seeds_from_roster(snap.get("roster") or [])


def _state(snap: dict) -> dict:
    return snap.get("state") or {}


def needed(t: dict) -> int:
    return max(2, int(t.get("min_players") or 2))


def _plan_start(snap: dict, now: datetime) -> list[Action]:
    t = snap["tournament"]
    starts = ts(t["starts_at"])
    if starts is None or starts > now:
        return [Hold(max(1, int((starts - now).total_seconds())) if starts else WAIT_RECHECK_S)]
    seeds = seeds_of(snap)
    need = needed(t)
    if len(seeds) >= need:
        actions: list[Action] = [GoLive()]
        if t["format"] != "arena":
            # Round one starts at once: there is no break before the first round.
            plan = service.plan_round({**t, "status": "live"}, seeds, [])
            if isinstance(plan, service.Pair):
                actions.append(PairRound(plan.round, plan.pairs, True))
            elif isinstance(plan, service.CannotPair):
                actions.append(Stalled(plan.reason))
        return actions
    have = f"{len(seeds)} of {need} players"
    mode = t.get("short_field") or "postpone"
    postponed = int(_state(snap).get("postponed") or 0)
    if mode == "postpone" and postponed < int(t.get("max_postpones") if t.get("max_postpones") is not None else 4):
        minutes = int(t.get("postpone_min") or 15)
        return [Postpone(minutes, f"Not enough players yet ({have}). Postponed by {minutes} minutes.")]
    if mode == "cancel":
        return [Cancel(f"Cancelled: only {have} by the start time.")]
    # wait, or postpone after its last postponement
    return [Hold(WAIT_RECHECK_S, f"Waiting for players ({have}). It starts as soon as {need} are in.")]


def _plan_rounds(snap: dict, now: datetime) -> list[Action]:
    t = snap["tournament"]
    rounds = snap.get("rounds") or []
    results = snap.get("results") or []
    brk = int(t.get("round_break_s") or 0)
    pending = sorted((r for r in rounds if r["status"] == "pending"), key=lambda r: r["number"])
    if pending:
        r = pending[0]
        due = break_over(r, results, brk)
        # "+5 min break" on the autopilot card sets hold_until
        # (autopilot_control); the round waits for that too.
        held = max(filter(None, [ts(_state(snap).get("hold_until")), ts(_state(snap).get("next_check_at"))]),
                   default=None)
        if held and held > due:
            due = held
        if due <= now:
            return [StartRound(r["id"], r["number"])]
        return [Hold(max(1, int((due - now).total_seconds())))]
    history = service.results_from_rows(results)
    plan = service.plan_round(t, seeds_of(snap), history)
    if isinstance(plan, service.Pair):
        # Round one never waits; later rounds are published at once and their
        # clocks start after the break, so players see who they face.
        return [PairRound(plan.round, plan.pairs, brk == 0 or not rounds)]
    if isinstance(plan, service.Done):
        return [Finish(plan.reason)]
    if isinstance(plan, service.CannotPair):
        return [Stalled(plan.reason)]
    return []  # Wait: a game is still on; its clock or its players end it


def break_over(round_row: dict, results: list[dict], brk: int) -> datetime:
    """When a published round may start: `round_break_s` after the later of
    its publication and the last game to finish (a knockout's tie-breaks reopen
    an old round, so its own timestamp alone would skip the break)."""
    marks = [ts(round_row.get("created_at"))] + [ts(g.get("finished_at")) for g in results if g.get("finished_at")]
    base = max(m for m in marks if m is not None)
    return base + timedelta(seconds=brk)


def _plan_arena(snap: dict, now: datetime) -> list[Action]:
    t = snap["tournament"]
    results = snap.get("results") or []
    started = ts(t.get("started_at"))
    end = started + timedelta(minutes=int(t["arena_minutes"])) if started else None
    playing = {p for g in results if g["status"] != "finished" for p in (g["white_id"], g["black_id"]) if p}
    if end is not None and now >= end:
        if any(g["status"] != "finished" for g in results):
            return []  # the window is shut; the last games finish (or flag) first
        return [Finish("the arena window has closed")]
    history = service.results_from_rows(results)
    seeds = {s.id: s for s in seeds_of(snap)}
    queue = sorted(snap.get("queue") or [], key=lambda q: q["since"])
    waiting = [seeds.get(q["user_id"], pairing.Seed(q["user_id"])) for q in queue if q["user_id"] not in playing]
    actions: list[Action] = []
    if len(waiting) >= 2:
        scores = service.arena_scores(waiting, history)
        # Longest-waiting first, each with the opponent arena_pick chooses -
        # the same choice a player arriving at the queue would get.
        while len(waiting) >= 2:
            pick = pairing.arena_pick(waiting[0].id, waiting, scores, history)
            if pick is None:
                break
            actions.append(ArenaPair(pick))
            waiting = [w for w in waiting if w.id not in (pick.white, pick.black)]
    if not actions and end is not None:
        return [Hold(max(1, min(WAIT_RECHECK_S, int((end - now).total_seconds()))))]
    return actions


# -----------------------------------------------------------------------------
# What the console shows: the next step and a timeline (GET .../autopilot,
# GET /v1/orgs/{org}/tournaments). Pure as well.
# -----------------------------------------------------------------------------
def next_step(t: dict, rounds: list[dict], results: list[dict], entrants: int, now: datetime,
              hold_until: Any = None) -> Optional[dict]:
    """{action, at, detail} - roughly what the tick will do next - or None."""
    status = t["status"]
    if status == "registration":
        need = needed(t)
        detail = f"starts if {need} or more are in ({entrants} so far)"
        return {"action": "start", "at": t.get("starts_at"), "detail": detail}
    if status != "live":
        return None
    if t["format"] == "arena":
        started = ts(t.get("started_at"))
        end = started + timedelta(minutes=int(t["arena_minutes"])) if started else None
        return {"action": "finish", "at": end.isoformat() if end else None, "detail": "when the arena window closes"}
    pending = sorted((r for r in rounds if r["status"] == "pending"), key=lambda r: r["number"])
    brk = int(t.get("round_break_s") or 0)
    if pending:
        r = pending[0]
        due = max(filter(None, [break_over(r, results, brk), ts(hold_until)]))
        return {"action": "start_round", "round": r["number"], "at": due.isoformat(),
                "detail": f"round {r['number']} starts after the break"}
    open_games = [g for g in results if g["status"] != "finished"]
    latest = max((g["round_number"] or 0 for g in results), default=0)
    if open_games:
        done = sum(1 for g in results if g["round_number"] == latest and g["status"] == "finished")
        total = sum(1 for g in results if g["round_number"] == latest)
        return {"action": "pair_round", "round": latest + 1, "at": None,
                "detail": f"round {latest} - {done} of {total} games finished"}
    last_round = t.get("rounds_count")
    if t["format"] == "swiss" and last_round and latest >= last_round:
        return {"action": "finish", "at": now.isoformat(), "detail": "every round has been played"}
    return {"action": "pair_round", "round": latest + 1, "at": now.isoformat(), "detail": "now"}


def brief_next(t: dict, now: datetime) -> Optional[dict]:
    """next_step without rounds or results, for lists of many tournaments."""
    if t["status"] == "registration":
        return {"action": "start", "at": t.get("starts_at"), "detail": f"starts if {needed(t)} or more are in"}
    if t["status"] != "live":
        return None
    if t["format"] == "arena":
        started = ts(t.get("started_at"))
        end = started + timedelta(minutes=int(t["arena_minutes"])) if started else None
        return {"action": "finish", "at": end.isoformat() if end else None, "detail": "when the arena window closes"}
    return {"action": "rounds", "at": None,
            "detail": t.get("autopilot_note") or "pairs each round when the last game of the previous one ends"}


def timeline(t: dict, rounds: list[dict], results: list[dict], entrants: int, now: datetime) -> list[dict]:
    """✓ entries opened · ● start · ○ round 1 · ○ rounds after the break · ○ finish.
    Each step: {key, label, state: done|current|next|todo, at?}."""
    status = t["status"]
    order = ["draft", "registration", "live", "finished"]
    pos = order.index(status) if status in order else len(order)
    steps = [{"key": "entries", "label": "Entries opened", "state": "done" if pos >= 1 else "todo", "at": None}]
    need = needed(t)
    steps.append({"key": "start", "label": f"Start, if {need} or more are in ({entrants} so far)",
                  "state": "done" if pos >= 2 else ("next" if pos == 1 else "todo"), "at": t.get("starts_at")})
    if t["format"] == "arena":
        started = ts(t.get("started_at"))
        end = started + timedelta(minutes=int(t["arena_minutes"])) if started else None
        steps.append({"key": "arena", "label": f"Arena open for {t['arena_minutes']} minutes",
                      "state": "current" if status == "live" else ("done" if pos >= 3 else "todo"),
                      "at": end.isoformat() if end else None})
    else:
        brk = int(t.get("round_break_s") or 0)
        by_number = {r["number"]: r for r in rounds}
        planned = t.get("rounds_count") or max([r["number"] for r in rounds] + [1])
        for n in range(1, int(planned) + 1):
            r = by_number.get(n)
            state = "todo"
            if r is not None:
                state = {"finished": "done", "live": "current", "pending": "next"}.get(r["status"], "todo")
            label = f"Round {n}" + (" at the start" if n == 1 else
                                    f", {_span(brk)} after the last game" if brk else
                                    ", as soon as the last game ends")
            steps.append({"key": f"round:{n}", "label": label, "state": state,
                          "at": (r or {}).get("started_at")})
    steps.append({"key": "finish", "label": "Finish", "state": "done" if pos >= 3 else "todo", "at": None})
    return steps


# -----------------------------------------------------------------------------
# Acting
# -----------------------------------------------------------------------------
Call = Callable[[str, dict], Any]


@dataclass
class Outcome:
    id: str
    lease: Optional[str] = None
    done: list[str] = field(default_factory=list)
    raced: list[str] = field(default_factory=list)
    error: Optional[str] = None
    retry_in: Optional[int] = None
    # None leaves tournaments.autopilot_note alone; "" clears it.
    note: Optional[str] = None
    stalled: bool = False

    def release(self) -> dict:
        """sys-release {lease, tournament, action?, error?, retry_in?, note?, stalled?}."""
        out: dict[str, Any] = {"lease": self.lease, "tournament": self.id}
        if self.done:
            out["action"] = ",".join(self.done)[:200]
        if self.error:
            out["error"] = self.error[:500]
        if self.retry_in is not None:
            out["retry_in"] = self.retry_in
        if self.note is not None:
            out["note"] = self.note[:500]
        if self.stalled:
            out["stalled"] = True
        return out


def _name(a: Action) -> str:
    if isinstance(a, PairRound):
        return f"pair:{a.round}"
    if isinstance(a, StartRound):
        return f"start_round:{a.number}"
    if isinstance(a, Flag):
        return f"flag:{a.game}"
    return type(a).__name__.lower()


# Steps that move an event on: whatever the note said ("Postponed...",
# "Waiting for players...") is no longer true once one of them succeeds.
_PROGRESS = (GoLive, PairRound, StartRound, ArenaPair, Finish)


def execute(snap: dict, actions: list[Action], call: Call) -> Outcome:
    """Turn one tournament's plan into sys-* calls. The main sequence (go
    live, then pair round one, ...) stops at its first refusal, because
    whatever refused it changed the state the rest was planned on; arena
    pairings are independent of each other."""
    t = snap["tournament"]
    out = Outcome(t["id"], snap.get("lease"))
    base = {"lease": snap.get("lease"), "tournament": t["id"]}
    for a in actions:
        try:
            if isinstance(a, GoLive):
                call("sys-status", {**base, "status": "live"})
            elif isinstance(a, PairRound):
                call("sys-pairings", {**base, "round": a.round, "start": a.start,
                                      "games": service.pairing_games(t, a.pairs)})
            elif isinstance(a, StartRound):
                call("sys-start-round", {**base, "round": a.round_id})
            elif isinstance(a, ArenaPair):
                call("sys-pairings", {**base, "round": None, "start": True,
                                      "games": service.pairing_games(t, [a.pairing])})
            elif isinstance(a, Finish):
                call("sys-status", {**base, "status": "finished"})
            elif isinstance(a, Cancel):
                call("sys-status", {**base, "status": "archived", "note": a.note})
            elif isinstance(a, Postpone):
                call("sys-postpone", {**base, "minutes": a.minutes, "note": a.note})
            elif isinstance(a, Hold):
                out.retry_in = a.seconds
                if a.note is not None:
                    out.note = a.note
                continue
            elif isinstance(a, Stalled):
                out.retry_in, out.stalled, out.error = a.seconds, True, a.reason
                out.note = f"Autopilot can't continue: {a.reason}. It will try again in {a.seconds // 60} minutes."
                continue
            out.done.append(_name(a))
            if isinstance(a, _PROGRESS) and out.note is None:
                out.note = ""
        except APIError as e:
            http = fail(e)
            if http.status_code in (404, 409):
                out.raced.append(_name(a))
                if isinstance(a, ArenaPair):
                    continue  # one game's race says nothing about the others
                break
            out.error = f"{_name(a)}: {http.detail}"
            break
        except Exception as e:  # noqa: BLE001 - one tournament must not stop the tick
            log.exception("autopilot action failed")
            out.error = f"{_name(a)}: {type(e).__name__}"
            break
    return out


def flag_all(flags: list[Flag], call: Call) -> dict:
    """sys-flag {game, ply, result}: no lease - the clock is the proof, checked
    again by the database. A flag that lost a race (a move landed, the player
    resigned) is simply not needed any more."""
    done, raced, errors = 0, 0, 0
    for f in flags:
        try:
            call("sys-flag", {"game": f.game, "ply": f.ply, "result": f.result})
            done += 1
        except APIError as e:
            if fail(e).status_code in (404, 409):
                raced += 1
            else:
                errors += 1
                log.warning("flag %s refused: %s", f.game, getattr(e, "code", None))
    return {"flagged": done, "raced": raced, "errors": errors}


def run_tick(call: Call = system_call, budget_s: float = BUDGET_S, clock: Callable[[], float] = time.monotonic,
             send_mail: Optional[Callable[[list[dict]], list[dict]]] = None) -> dict:
    """One tick: work, flags, plan and act, series, mail, release. Whatever
    the budget does not reach is released untouched and leased again on the
    next tick."""
    began = clock()
    # mail_on: the database cannot see this API's environment, and without it
    # an unsent invite would keep autopilot_due() true - and the database
    # kicking a tick every 10 s that skips mail - for as long as Resend is
    # not configured. Told it is off, it asks again only now and then.
    work = call("sys-work", {"limit": LEASE_LIMIT, "mail_on": settings.mail_on}) or {}
    snaps = work.get("tournaments") or []
    db_now = ts(work.get("server_now")) or datetime.now(timezone.utc)

    def left() -> float:
        return budget_s - (clock() - began)

    flagged = flag_all(plan_flags(work.get("flags") or []), call)
    outcomes: list[Outcome] = []
    rolled = 0
    for snap in snaps:
        if left() < 0:
            rolled += 1
            outcomes.append(Outcome(snap["tournament"]["id"], snap.get("lease")))
            continue
        try:
            plan = plan_tournament(snap, db_now + timedelta(seconds=clock() - began))
        except Exception as e:  # noqa: BLE001
            log.exception("autopilot planning failed")
            outcomes.append(Outcome(snap["tournament"]["id"], snap.get("lease"), error=f"plan: {type(e).__name__}"))
            continue
        outcomes.append(execute(snap, plan, call))

    series, series_errors = [], []
    for sid in work.get("series") or []:
        if left() < 0:
            break
        try:
            got = call("sys-series", {"series": sid}) or {}
            series.append(got.get("created"))
            # A template that cannot make an instance: the database wrote it
            # on the series and holds it for five minutes (series_next_safe).
            if got.get("error"):
                series_errors.append({"series": sid, "error": got["error"]})
                log.warning("series %s: %s", sid, got["error"])
        except APIError as e:
            series_errors.append({"series": sid, "error": fail(e).detail})
            log.warning("series %s: %s", sid, fail(e).detail)

    mail = {"sent": 0, "failed": 0, "on": settings.mail_on}
    if settings.mail_on and work.get("mail") and left() >= MAIL_MIN_LEFT_S:
        mail.update(_mail_step(call, send_mail))

    for o in outcomes:
        try:
            call("sys-release", o.release())
        except APIError as e:
            # A lapsed lease (60 s) releases itself; nothing to undo.
            log.warning("release %s: %s", o.id, fail(e).detail)
    return {
        "ok": True,
        "leased": len(snaps),
        "rolled_over": rolled,
        "flags": flagged,
        "tournaments": [{"id": o.id, "done": o.done, "raced": o.raced, "error": o.error} for o in outcomes],
        "series": [x.get("slug") for x in series if isinstance(x, dict)],
        "series_errors": series_errors,
        "mail": mail,
        "ms": int((clock() - began) * 1000),
    }


def _mail_step(call: Call, send_mail: Optional[Callable[[list[dict]], list[dict]]]) -> dict:
    """sys-mail-batch -> Resend -> sys-mail-done. Transient failures are not
    reported back: the batch's two-minute hold lapses and they go again."""
    import mail as mailer  # httpx only loads when there is mail to send

    batch = call("sys-mail-batch", {"limit": MAIL_BATCH}) or {}
    messages = mailer.from_batch(batch)
    if not messages:
        return {}
    results = (send_mail or mailer.send_outbox)(messages)
    report = mailer.to_done(results)
    if report["invites"] or report["outbox"]:
        call("sys-mail-done", report)
    return {"sent": sum(1 for r in results if r.get("ok")), "failed": sum(1 for r in results if not r.get("ok")),
            "retry": sum(1 for r in results if not r.get("ok") and not r.get("permanent"))}
