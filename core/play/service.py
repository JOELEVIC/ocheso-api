"""
The referee's judgement, once, for everyone who plays through this API.

Three doors lead to the same rulings: the console's routes (routers/play.py,
a player's sign-in token), the embed (routers/embed.py, an oche_ session) and
the autopilot (autopilot.py, nobody at all). Each reads the game its own way
and signs for the database its own way, but what counts as a legal move, who
won on time, what the next round is and how a table is drawn up live here, so
the three can never disagree about chess.

Nothing here talks to the database. Functions take what was read and return
what to sign; the routes raise the HTTP answers, which is why a few of these
raise HTTPException with the same words the console has always used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional, Union

from fastapi import HTTPException

from play import pairing, rules, standings


def variant(t: dict) -> str:
    return "standard" if t["game"] == "chess" else t["variant"]


# -----------------------------------------------------------------------------
# Reading the record
# -----------------------------------------------------------------------------
def seeds_from_roster(roster: Iterable[dict]) -> list[pairing.Seed]:
    """Approved players in seeding order: seed, then rating, then who came
    first. `roster` rows are get_roster's (user_id, rating_at_entry, seed,
    joined_at); the autopilot's snapshot and the embed bundle carry the same."""
    ordered = sorted(roster, key=lambda p: (p.get("seed") or 10**6, -(p.get("rating_at_entry") or 0), p["joined_at"]))
    return [pairing.Seed(p["user_id"], p.get("rating_at_entry") or 0) for p in ordered]


def results_from_rows(found: Iterable[dict]) -> list[standings.Result]:
    """get_results rows as the scoreboard reads them."""
    return [
        standings.Result(
            round=g["round_number"],
            white=g["white_id"],
            black=g["black_id"],
            result=g["result"] if g["status"] == "finished" else None,
            board=g["board"],
            tiebreak_of=g["tiebreak_of"],
            game_id=g["game_id"],
            finished=g["status"] == "finished",
        )
        for g in found
    ]


def history_of(game: dict, moves: list[dict]) -> list[str]:
    """The game's moves in order, refusing a record that has not fully arrived
    (a move row lags the game row it belongs to)."""
    if len(moves) != game["ply"]:
        raise HTTPException(status_code=409, detail="The game record is still arriving. Try again.")
    return [m["move"] for m in sorted(moves, key=lambda m: m["ply"])]


# -----------------------------------------------------------------------------
# Pairings
# -----------------------------------------------------------------------------
def pairing_games(t: dict, pairs: list[pairing.Pairing]) -> list[dict]:
    """The `games` of a pairings ruling: every board starts from the rules'
    opening position, so the database never has to know one."""
    begin = rules.start(t["game"], variant(t))
    return [
        {
            "board": p.board or None,
            "white": p.white,
            "black": p.black,
            "position": begin.position,
            "turn": begin.turn,
            "legal": begin.legal,
            "tiebreak_of": p.tiebreak_of,
        }
        for p in pairs
    ]


@dataclass(frozen=True)
class Pair:
    """Publish these pairings as round `round` (a knockout's tie-breaks reuse
    the round they settle)."""

    round: int
    pairs: list[pairing.Pairing] = field(default_factory=list)


@dataclass(frozen=True)
class Done:
    """Nothing left to pair: the event is complete."""

    reason: str


@dataclass(frozen=True)
class Wait:
    """A game of the current round is still being played."""

    reason: str = "games in this round are still being played"


@dataclass(frozen=True)
class CannotPair:
    """Pairing is impossible as things stand; a person has to look."""

    reason: str


Plan = Union[Pair, Done, Wait, CannotPair]

# pairing.knockout says "complete" by raising, like any other refusal; for a
# planner that is the difference between finishing the event and calling for help.
_KNOCKOUT_OVER = "the knockout is complete"


def plan_round(t: dict, seeds: list[pairing.Seed], history: list[standings.Result]) -> Plan:
    """What the next round of a round-based event is - for an organiser
    pressing "pair next round" and for the autopilot alike.

    The reasons are the console's own wording (routers/play.py turns them into
    its 409s), so moving this here changed no answer anyone sees."""
    if t["format"] == "arena":
        return CannotPair("an arena pairs players as they become free")
    if any(r.result is None for r in history):
        return Wait()
    latest = max((r.round or 0 for r in history), default=0)
    try:
        if t["format"] == "knockout":
            round_no, pairs = pairing.knockout(seeds, history)
        elif t["format"] == "round_robin":
            if not history:
                total = pairing.round_robin_rounds(len(seeds))
            else:
                # The field was fixed by round one; later withdrawals keep their slot.
                total = pairing.round_robin_rounds(len({x for r in history if r.round == 1 for x in (r.white, r.black) if x}))
            round_no = latest + 1
            if round_no > total:
                return Done("every round has been played")
            order = rr_order(history, seeds) if latest else seeds
            pairs = pairing.round_robin(order, round_no)
        else:
            round_no = latest + 1
            if t.get("rounds_count") and round_no > t["rounds_count"]:
                return Done("every round has been played")
            pairs = pairing.swiss(seeds, history, round_no)
    except pairing.CannotPair as e:
        return Done(str(e)) if str(e) == _KNOCKOUT_OVER else CannotPair(str(e))
    return Pair(round_no, pairs)


def rr_order(history: list[standings.Result], seeds: list[pairing.Seed]) -> list[pairing.Seed]:
    """The round robin's seating is fixed by its first round, so later rounds
    use the same order even if someone has since withdrawn."""
    first = sorted((r for r in history if r.round == 1), key=lambda r: r.board or 0)
    ids = {s.id: s for s in seeds}
    seen: list[str] = []
    for r in first:
        for who in (r.white, r.black):
            if who and who not in seen:
                seen.append(who)
    by_seed = {s.id: i for i, s in enumerate(seeds)}
    seen.sort(key=lambda pid: by_seed.get(pid, 10**6))
    return [ids.get(pid, pairing.Seed(pid)) for pid in seen]


def arena_scores(waiting: list[pairing.Seed], history: list[standings.Result]) -> dict[str, float]:
    return {l.player: l.points for l in standings.arena({s.id: s.rating for s in waiting}, history)}


# -----------------------------------------------------------------------------
# Moves and flags
# -----------------------------------------------------------------------------
def check_live(game: dict) -> None:
    if game["status"] != "live":
        raise HTTPException(status_code=409, detail="This game is not in progress.")


def check_mover(game: dict, by: Optional[str], ply: Optional[int]) -> str:
    """Said plainly before judging: "e7e5 is not legal here" is true when it is
    White's move, but "not your move" is what the player needs to hear. The
    database checks all of this again."""
    check_live(game)
    side = "white" if by == game["white_id"] else "black" if by == game["black_id"] else None
    if side is None:
        raise HTTPException(status_code=403, detail="You're not playing this game.")
    if side != game["turn"]:
        raise HTTPException(status_code=409, detail="It's not your move.")
    if ply is not None and ply != game["ply"]:
        raise HTTPException(status_code=409, detail="The position has moved on. Your board will catch up.")
    return side


def move_ruling(game: dict, history: list[str], move: str) -> dict:
    """The body of a move ruling (db/play.sql play_move's payload, less kind,
    by and exp, which the signer adds)."""
    t = game["tournament"]
    # The record and the stored position must agree before anything is built on
    # either: if they ever do not, stop rather than rule on the wrong board.
    if rules.position_after(t["game"], variant(t), history) != game["position"]:
        raise HTTPException(status_code=500, detail="This game's record is inconsistent. An organiser has to look at it.")
    try:
        r = rules.judge(t["game"], variant(t), history, move)
    except rules.Illegal as e:
        raise HTTPException(status_code=422, detail=str(e).capitalize() + ".")
    return {
        "game": game["id"],
        "ply": game["ply"],
        "before": game["position"],
        "move": r.move,
        "san": r.san,
        "after": r.after.position,
        "turn": r.after.turn,
        "legal": r.after.legal,
        "result": r.result,
        "termination": r.termination,
    }


def flag_ruling(game: dict, history: list[str]) -> dict:
    """Out of time loses - unless the opponent could never have won. The
    database checks the clock itself; this rules only on the result."""
    t = game["tournament"]
    return {"game": game["id"], "ply": game["ply"], "result": rules.flag_result(t["game"], variant(t), history)}


# -----------------------------------------------------------------------------
# What the public sees: the table and the rounds
# -----------------------------------------------------------------------------
def standings_table(t: dict, seeds: list[pairing.Seed], results: list[standings.Result]):
    """(players with ratings, ranked lines). Someone removed after playing
    still counts for others' tie-breaks."""
    players = {s.id: s.rating for s in seeds}
    for r in results:
        for who in (r.white, r.black):
            if who and who not in players:
                players[who] = 0
    if t["format"] == "arena":
        lines = standings.arena(players, results)
    else:
        lines = standings.table(players, results, t["tiebreaks"])
    return players, lines


def standings_out(t: dict, results: list[standings.Result], lines: list[standings.Line], names: dict[str, dict]) -> dict:
    return {
        "format": t["format"],
        "tiebreaks": [] if t["format"] == "arena" else t["tiebreaks"],
        "champion": pairing.knockout_champion(results) if t["format"] == "knockout" else None,
        "lines": [
            {
                "rank": l.rank,
                "player": names.get(l.player) or {"id": l.player},
                "points": l.points,
                "played": l.played,
                "wins": l.wins,
                "byes": l.byes,
                "rating": l.rating,
                "tiebreaks": l.tiebreaks,
            }
            for l in lines
        ],
    }


def rounds_out(results: list[dict], round_rows: list[dict], names: dict[str, dict]) -> list[dict]:
    """get_results rows grouped by round. Round ids come from the rounds table,
    which only staff and entrants of an unlisted event can read; everyone else
    gets the status from the results."""
    meta = {r["number"]: r for r in round_rows}
    for g in results:
        if g["round_number"] is not None and g["round_number"] not in meta:
            meta[g["round_number"]] = {"id": None, "status": g["round_status"], "started_at": None}
    rounds: dict[Optional[int], list[dict]] = {}
    for g in results:
        rounds.setdefault(g["round_number"], []).append(
            {
                "id": g["game_id"],
                "board": g["board"],
                "white": names.get(g["white_id"]),
                "black": names.get(g["black_id"]),
                "status": g["status"],
                "result": g["result"],
                "termination": g["termination"],
                "tiebreak_of": g["tiebreak_of"],
            }
        )
    return [
        {
            "number": n,
            "id": (meta.get(n) or {}).get("id"),
            "status": (meta.get(n) or {}).get("status", "live" if n is None else "pending"),
            "started_at": (meta.get(n) or {}).get("started_at"),
            "games": games,
        }
        for n, games in sorted(rounds.items(), key=lambda kv: (kv[0] is None, kv[0] or 0))
    ]
