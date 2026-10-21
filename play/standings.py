"""
Scores and tie-breaks, from the results alone.

A win is 1, a draw ½, a bye 1 (a full-point bye, the common club rule), a
double forfeit nothing for either. Arena scores differently - see `arena`.
Ties are broken in the order the organiser chose, then by rating.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass(frozen=True)
class Result:
    """One game, as the scoreboard sees it."""

    round: Optional[int]
    white: str
    black: Optional[str]          # None: a bye
    result: Optional[str]         # "white" | "black" | "draw" | "none" | None (unfinished)
    board: Optional[int] = None
    tiebreak_of: Optional[str] = None
    game_id: Optional[str] = None
    finished: bool = True


@dataclass
class Line:
    player: str
    rating: int = 0
    points: float = 0.0
    played: int = 0
    wins: int = 0
    byes: int = 0
    colours: list[str] = field(default_factory=list)      # "W" / "B" per game played
    opponents: list[str] = field(default_factory=list)
    scored: list[tuple[str, float]] = field(default_factory=list)  # (opponent, points)
    by_round: list[float] = field(default_factory=list)   # points after each round
    tiebreaks: dict[str, float] = field(default_factory=dict)
    rank: int = 0


def points_for(r: Result, player: str) -> Optional[float]:
    if r.result is None:
        return None
    if r.black is None:
        return 1.0
    if r.result == "draw":
        return 0.5
    if r.result == "none":
        return 0.0
    mine = "white" if r.white == player else "black"
    return 1.0 if r.result == mine else 0.0


def table(
    players: dict[str, int],
    results: Iterable[Result],
    tiebreaks: Iterable[str] = ("buchholz", "sonneborn_berger"),
) -> list[Line]:
    """Ranked lines for every player. `players` maps id -> rating."""
    lines = {p: Line(p, rating=r) for p, r in players.items()}
    rounds: dict[int, list[Result]] = {}
    for r in results:
        if r.result is None:
            continue
        rounds.setdefault(r.round or 0, []).append(r)

    for n in sorted(rounds):
        for r in rounds[n]:
            for who in (r.white, r.black):
                if who is None or who not in lines:
                    continue
                line = lines[who]
                got = points_for(r, who) or 0.0
                line.points += got
                if r.black is None:
                    line.byes += 1
                    continue
                opp = r.black if who == r.white else r.white
                line.played += 1
                line.colours.append("W" if who == r.white else "B")
                line.opponents.append(opp)
                line.scored.append((opp, got))
                if got == 1.0 and r.result != "none":
                    line.wins += 1
        for line in lines.values():
            line.by_round.append(line.points)

    score = {p: l.points for p, l in lines.items()}
    order = list(tiebreaks)
    for line in lines.values():
        opp_scores = [score.get(o, 0.0) for o in line.opponents]
        for tb in order:
            if tb == "buchholz":
                line.tiebreaks[tb] = sum(opp_scores)
            elif tb == "buchholz_cut1":
                line.tiebreaks[tb] = sum(opp_scores) - (min(opp_scores) if opp_scores else 0.0)
            elif tb == "sonneborn_berger":
                line.tiebreaks[tb] = sum(score.get(o, 0.0) * got for o, got in line.scored)
            elif tb == "wins":
                line.tiebreaks[tb] = float(line.wins)
            elif tb == "progressive":
                line.tiebreaks[tb] = sum(line.by_round)

    if "direct_encounter" in order:
        # Points scored against the others on the same score - meaningful only
        # among players who have all met, which is the rule's own condition.
        groups: dict[float, list[Line]] = {}
        for line in lines.values():
            groups.setdefault(line.points, []).append(line)
        for group in groups.values():
            ids = {l.player for l in group}
            for l in group:
                l.tiebreaks["direct_encounter"] = sum(got for o, got in l.scored if o in ids)

    ranked = sorted(
        lines.values(),
        key=lambda l: (-l.points, *(-l.tiebreaks.get(tb, 0.0) for tb in order), -l.rating, l.player),
    )
    for i, l in enumerate(ranked, 1):
        l.rank = i
    return ranked


def arena(players: dict[str, int], results: Iterable[Result]) -> list[Line]:
    """
    Arena scoring: 2 for a win, 1 for a draw. Two wins in a row light a streak
    that doubles every result until it breaks - so a run of form is worth more
    than the same wins scattered, which is what keeps an arena moving.
    """
    lines = {p: Line(p, rating=r) for p, r in players.items()}
    streak: dict[str, int] = {p: 0 for p in players}
    for r in sorted((r for r in results if r.result is not None and r.black is not None),
                    key=lambda r: r.round or 0):
        for who in (r.white, r.black):
            if who not in lines:
                continue
            got = points_for(r, who) or 0.0
            line = lines[who]
            base = 2 if got == 1.0 else 1 if got == 0.5 else 0
            line.points += base * (2 if streak[who] >= 2 else 1)
            line.played += 1
            line.opponents.append(r.black if who == r.white else r.white)
            line.colours.append("W" if who == r.white else "B")
            if got == 1.0:
                line.wins += 1
                streak[who] += 1
            else:
                streak[who] = 0
    ranked = sorted(lines.values(), key=lambda l: (-l.points, -l.wins, -l.rating, l.player))
    for i, l in enumerate(ranked, 1):
        l.rank = i
        l.tiebreaks["streak"] = float(streak[l.player])
    return ranked
