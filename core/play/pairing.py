"""
Who plays whom, and with which colour.

    round_robin(players, round_no)           Berger tables
    knockout(players, history, round_no)     seeded bracket, tie-breaks on draws
    swiss(players, history, round_no)        weighted matching, Dutch priorities
    arena_pick(me, waiting, history)         the best opponent free right now

`players` is a list of Seed (id, rating) in seeding order: strongest first,
which is how every system here reads "top half" and "first seed".

Swiss is not a certified FIDE Dutch implementation. It pairs by maximum-weight
matching over every possible pairing, with weights ordered the way the Dutch
system orders its criteria: no rematches (absolute, unless nothing else is
possible), then absolute colour clashes, then the smallest score differences,
then mild colour preferences, then top half against bottom half within a score
group. That gets the answers people expect from a Swiss and never deadlocks,
which hand-rolled backtracking does in the late rounds of small events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from play.standings import Result, points_for


@dataclass(frozen=True)
class Seed:
    id: str
    rating: int = 0


@dataclass(frozen=True)
class Pairing:
    board: int
    white: str
    black: Optional[str]           # None: a bye
    tiebreak_of: Optional[str] = None


class CannotPair(ValueError):
    pass


# -----------------------------------------------------------------------------
# Round robin
# -----------------------------------------------------------------------------
def round_robin_rounds(n_players: int) -> int:
    return n_players - 1 if n_players % 2 == 0 else n_players


def round_robin(players: list[Seed], round_no: int) -> list[Pairing]:
    """Round `round_no` (1-based) of the Berger table for these players."""
    ids: list[Optional[str]] = [p.id for p in players]
    if len(ids) < 2:
        raise CannotPair("a round robin needs at least two players")
    if len(ids) % 2:
        ids.append(None)  # the bye
    n = len(ids)
    if not 1 <= round_no <= n - 1:
        raise CannotPair(f"a round robin of {len(players)} has {n - 1} rounds")

    # Circle method: the first seat stays, the rest rotate one place a round.
    seats = ids[:]
    for _ in range(round_no - 1):
        seats = [seats[0], seats[-1], *seats[1:-1]]

    out: list[Pairing] = []
    for i in range(n // 2):
        a, b = seats[i], seats[n - 1 - i]
        # Alternate colours by round on the fixed seat, by board elsewhere, so
        # nobody plays three of a colour running and counts come out even.
        swap = (round_no % 2 == 0) if i == 0 else (i % 2 == 1)
        white, black = (b, a) if swap else (a, b)
        if white is None:
            white, black = black, None
        out.append(Pairing(0, white, black))  # type: ignore[arg-type]
    return _boards(out)


# -----------------------------------------------------------------------------
# Knockout
# -----------------------------------------------------------------------------
def _bracket_order(size: int) -> list[int]:
    """Seed numbers in bracket order, so 1 and 2 can only meet in the final."""
    order = [1]
    while len(order) < size:
        m = len(order) * 2 + 1
        order = [x for s in order for x in (s, m - s)]
    return order


def knockout_rounds(n_players: int) -> int:
    size = 1
    while size < n_players:
        size *= 2
    return max(1, size.bit_length() - 1)


@dataclass
class Match:
    board: int
    a: str
    b: Optional[str]
    games: list[Result]

    def winner(self) -> Optional[str]:
        if self.b is None:
            return self.a
        # The last decisive game settles it; draws send it to a tie-break.
        for g in reversed(self.games):
            if g.result in ("white", "black"):
                return g.white if g.result == "white" else g.black
            if g.result == "none":
                return None
        return None

    def open(self) -> bool:
        return any(g.result is None for g in self.games)


def knockout_matches(history: list[Result], round_no: int) -> list[Match]:
    by_board: dict[int, Match] = {}
    for g in history:
        if g.round != round_no:
            continue
        board = g.board or 0
        m = by_board.get(board)
        if m is None:
            m = by_board[board] = Match(board, g.white, g.black, [])
        m.games.append(g)
    return [by_board[b] for b in sorted(by_board)]


def knockout(players: list[Seed], history: list[Result]) -> tuple[int, list[Pairing]]:
    """
    (round number, pairings) for whatever the bracket needs next. A drawn match
    gets a tie-break game in its own round, colours reversed; once every match
    is decided, the winners meet in the next round. Raises when it is over.
    """
    latest = max((g.round or 0 for g in history), default=0)
    if latest == 0:
        if len(players) < 2:
            raise CannotPair("a knockout needs at least two players")
        size = 1
        while size < len(players):
            size *= 2
        seeds = {i + 1: p.id for i, p in enumerate(players)}
        order = _bracket_order(size)
        out = []
        for i in range(0, size, 2):
            a, b = seeds.get(order[i]), seeds.get(order[i + 1])
            if a is None:
                a, b = b, None
            # The higher seed takes White in the first round; the top seeds,
            # facing empty slots, get the byes.
            out.append(Pairing(i // 2 + 1, a, b))  # type: ignore[arg-type]
        return 1, out

    matches = knockout_matches(history, latest)
    if any(m.open() for m in matches):
        raise CannotPair("games in this round are still being played")

    undecided = [m for m in matches if m.winner() is None]
    if undecided:
        # Same board, colours reversed. A double forfeit is replayed too.
        return latest, [
            Pairing(m.board, m.games[-1].black, m.games[-1].white, tiebreak_of=m.games[-1].game_id)  # type: ignore[arg-type]
            for m in undecided
        ]

    winners = [m.winner() for m in matches]
    if len(winners) == 1:
        raise CannotPair("the knockout is complete")
    out = []
    for i in range(0, len(winners), 2):
        a = winners[i]
        b = winners[i + 1] if i + 1 < len(winners) else None
        # Whoever came from the upper half starts with White in odd rounds.
        white, black = (a, b) if (latest + 1) % 2 == 1 or b is None else (b, a)
        out.append(Pairing(i // 2 + 1, white, black))  # type: ignore[arg-type]
    return latest + 1, out


def knockout_champion(history: list[Result]) -> Optional[str]:
    latest = max((g.round or 0 for g in history), default=0)
    matches = knockout_matches(history, latest)
    if len(matches) == 1 and not matches[0].open():
        return matches[0].winner()
    return None


# -----------------------------------------------------------------------------
# Swiss
# -----------------------------------------------------------------------------
@dataclass
class _Profile:
    id: str
    rating: int
    rank: int
    score: float
    colours: list[str]
    opponents: set[str]
    had_bye: bool

    @property
    def balance(self) -> int:
        return self.colours.count("W") - self.colours.count("B")

    def wants(self) -> tuple[Optional[str], int]:
        """(colour, strength): 2 absolute, 1 strong, 0 none."""
        last2 = self.colours[-2:]
        if self.balance <= -2 or last2 == ["B", "B"]:
            return "W", 2
        if self.balance >= 2 or last2 == ["W", "W"]:
            return "B", 2
        if self.balance == -1:
            return "W", 1
        if self.balance == 1:
            return "B", 1
        if self.colours:
            return ("B" if self.colours[-1] == "W" else "W"), 1
        return None, 0


def _profiles(players: list[Seed], history: list[Result]) -> list[_Profile]:
    profs = {p.id: _Profile(p.id, p.rating, i, 0.0, [], set(), False) for i, p in enumerate(players)}
    for g in sorted(history, key=lambda g: g.round or 0):
        if g.result is None:
            continue
        for who in (g.white, g.black):
            if who not in profs:
                continue
            pr = profs[who]
            pr.score += points_for(g, who) or 0.0
            if g.black is None:
                pr.had_bye = True
            else:
                pr.colours.append("W" if who == g.white else "B")
                pr.opponents.add(g.black if who == g.white else g.white)
    return list(profs.values())


def swiss(players: list[Seed], history: list[Result], round_no: int) -> list[Pairing]:
    if len(players) < 2:
        raise CannotPair("a Swiss needs at least two players")
    if any(g.result is None for g in history):
        raise CannotPair("games in this round are still being played")

    profs = _profiles(players, history)
    out: list[Pairing] = []

    if len(profs) % 2:
        # The bye goes to the lowest-placed player who has not had one.
        eligible = [p for p in profs if not p.had_bye] or profs
        bye = min(eligible, key=lambda p: (p.score, -p.rank))
        profs.remove(bye)
        bye_pairing = Pairing(0, bye.id, None)
    else:
        bye_pairing = None

    if round_no == 1 or all(not p.colours for p in profs) and all(p.score == 0 for p in profs):
        ordered = sorted(profs, key=lambda p: p.rank)
        half = len(ordered) // 2
        for i in range(half):
            top, bottom = ordered[i], ordered[i + half]
            white, black = (top, bottom) if i % 2 == 0 else (bottom, top)
            out.append(Pairing(0, white.id, black.id))
    else:
        out = _swiss_match(profs)

    if bye_pairing:
        out.append(bye_pairing)
    return _boards(out, score={p.id: p.score for p in _profiles(players, history)}, rank={p.id: i for i, p in enumerate(players)})


def _swiss_match(profs: list[_Profile]) -> list[Pairing]:
    # Score groups, strongest first, each sorted by seed: "top half v bottom half".
    groups: dict[float, list[_Profile]] = {}
    for p in profs:
        groups.setdefault(p.score, []).append(p)
    place: dict[str, tuple[int, int]] = {}
    for score, members in groups.items():
        members.sort(key=lambda p: p.rank)
        for i, p in enumerate(members):
            place[p.id] = (i, len(members))

    g = nx.Graph()
    for i, a in enumerate(profs):
        for b in profs[i + 1:]:
            weight = 10**12
            if b.id in a.opponents:
                weight -= 9 * 10**11  # only when nothing else is possible
            (wa, sa), (wb, sb) = a.wants(), b.wants()
            if sa == 2 and sb == 2 and wa == wb:
                weight -= 10**10      # absolute colour clash
            diff = int(abs(a.score - b.score) * 2)
            weight -= diff * diff * 10**8
            if wa is not None and wa == wb:
                weight -= (sa + sb) * 10**5
            if a.score == b.score:
                (ia, size), (ib, _) = place[a.id], place[b.id]
                weight -= abs(abs(ia - ib) - size // 2) * 10**2
            else:
                weight -= abs(a.rank - b.rank)
            g.add_edge(a.id, b.id, weight=weight)

    matched = nx.max_weight_matching(g, maxcardinality=True)
    if len(matched) * 2 != len(profs):
        raise CannotPair("these players cannot all be paired")

    by_id = {p.id: p for p in profs}
    out = []
    for x, y in matched:
        a, b = by_id[x], by_id[y]
        out.append(Pairing(0, *_colours(a, b)))
    return out


def _colours(a: _Profile, b: _Profile) -> tuple[str, str]:
    (wa, sa), (wb, sb) = a.wants(), b.wants()
    if wa != wb:
        if wa == "W" or wb == "B":
            return a.id, b.id
        if wa == "B" or wb == "W":
            return b.id, a.id
    if sa != sb:
        # The stronger preference gets its way.
        strong, other = (a, b) if sa > sb else (b, a)
        want = strong.wants()[0]
        return (strong.id, other.id) if want == "W" else (other.id, strong.id)
    # Equal: the higher seed alternates from their last colour, or takes White.
    higher, lower = (a, b) if a.rank < b.rank else (b, a)
    if higher.colours and higher.colours[-1] == "W":
        return lower.id, higher.id
    return higher.id, lower.id


# -----------------------------------------------------------------------------
# Arena
# -----------------------------------------------------------------------------
def arena_pick(me: str, waiting: list[Seed], scores: dict[str, float], history: list[Result]) -> Optional[Pairing]:
    """The opponent for `me` among those waiting: nearest score, then nearest
    rating, avoiding whoever they just played if anyone else is free."""
    others = [w for w in waiting if w.id != me]
    if not others:
        return None
    mine = next((w for w in waiting if w.id == me), Seed(me))
    last = None
    for g in reversed(history):
        if me in (g.white, g.black) and g.black is not None:
            last = g.black if g.white == me else g.white
            break
    pool = [o for o in others if o.id != last] or others
    best = min(pool, key=lambda o: (abs(scores.get(o.id, 0) - scores.get(me, 0)), abs(o.rating - mine.rating)))
    # White to whoever has had it less.
    def whites(pid: str) -> int:
        return sum(1 for g in history if g.white == pid and g.black is not None) - sum(
            1 for g in history if g.black == pid
        )
    white, black = (me, best.id) if whites(me) <= whites(best.id) else (best.id, me)
    return Pairing(0, white, black)


# -----------------------------------------------------------------------------
def _boards(
    pairings: list[Pairing], score: Optional[dict[str, float]] = None, rank: Optional[dict[str, int]] = None
) -> list[Pairing]:
    """Number the boards: top scores first, byes last."""
    score = score or {}
    rank = rank or {}

    def key(p: Pairing):
        if p.black is None:
            return (1, 0.0, 0)
        top = max(score.get(p.white, 0), score.get(p.black, 0))
        best = min(rank.get(p.white, 10**6), rank.get(p.black, 10**6))
        return (0, -top, best)

    ordered = sorted(pairings, key=key)
    return [Pairing(i, p.white, p.black, p.tiebreak_of) for i, p in enumerate(ordered, 1)]
