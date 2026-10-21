"""
Playing: rounds, pairings, moves, the clock, results, standings, the arena.

The API is the referee here. It reads the game as the caller, judges the move
with the rules engine (play/rules.py), and hands the database a signed ruling
(play/referee.py). The database decides whether the caller may act on it - the
right player, the right ply, time on the clock - so this module never has to
be trusted with that, and a client calling the database directly gets nothing
it could not get through here.
"""

from __future__ import annotations

from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from db import CallerDb, UserDb, one, rows
from play import pairing, rules, standings
from play.referee import caller_id, sign
from routers.tournaments import find

router = APIRouter(tags=["Play"])

Auth = Annotated[Optional[str], Header(alias="Authorization")]

PERSON = "id,username,display_name,avatar_url,country"
GAME_FULL = (
    "*, tournament:tournaments(id,slug,title,game,variant,format,status,games_watchable),"
    f" white:profiles!games_white_id_fkey({PERSON}), black:profiles!games_black_id_fkey({PERSON})"
)


class MoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    move: str = Field(min_length=2, max_length=64)
    # The ply the player saw. If the game has moved on, refuse rather than
    # apply a move made against a position that no longer exists.
    ply: Optional[int] = Field(None, ge=0)


class NextIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Publish and start the clocks at once, or publish for players to see first.
    start: bool = False


class ResultIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result: Literal["white", "black", "draw", "none"]


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _variant(t: dict) -> str:
    return "standard" if t["game"] == "chess" else t["variant"]


def _seeds(db, slug: str) -> list[pairing.Seed]:
    """Approved players in seeding order: seed, then rating, then who came first."""
    roster = rows(db.rpc("get_roster", {"p_slug": slug}).execute())
    roster.sort(key=lambda p: (p.get("seed") or 10**6, -(p.get("rating_at_entry") or 0), p["joined_at"]))
    return [pairing.Seed(p["user_id"], p.get("rating_at_entry") or 0) for p in roster]


def _results(db, tournament_id: str) -> list[standings.Result]:
    out = []
    for g in rows(db.rpc("get_results", {"p_tournament": tournament_id}).execute()):
        out.append(
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
        )
    return out


def _people(db, ids) -> dict[str, dict]:
    ids = sorted({i for i in ids if i})
    if not ids:
        return {}
    return {p["id"]: p for p in rows(db.table("profiles").select(PERSON).in_("id", ids).execute())}


def _game(db, game_id: str) -> dict:
    return one(db.table("games").select(GAME_FULL).eq("id", game_id).execute(), missing="No such game.")


def _history(db, game: dict) -> list[str]:
    moves = rows(db.table("moves").select("ply,move").eq("game_id", game["id"]).order("ply").execute())
    if len(moves) != game["ply"]:
        raise HTTPException(status_code=409, detail="The game record is still arriving. Try again.")
    return [m["move"] for m in moves]


def _publish(db, by: str, t: dict, round_no: Optional[int], pairs: list[pairing.Pairing], start: bool) -> list[dict]:
    begin = rules.start(t["game"], _variant(t))
    games = [
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
    payload, sig = sign("pairings", by, {"tournament": t["id"], "round": round_no, "start": start, "games": games})
    return rows(db.rpc("publish_pairings", {"p_payload": payload, "p_sig": sig}).execute())


# -----------------------------------------------------------------------------
# Rounds and standings
# -----------------------------------------------------------------------------
@router.get("/v1/tournaments/{slug}/rounds", summary="Pairings and results, round by round")
def list_rounds(slug: str, db: CallerDb):
    t = find(db, slug)
    results = rows(db.rpc("get_results", {"p_tournament": t["id"]}).execute())
    meta = {r["number"]: r for r in rows(db.table("rounds").select("*").eq("tournament_id", t["id"]).execute())}
    names = _people(db, [g["white_id"] for g in results] + [g["black_id"] for g in results])
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


@router.get("/v1/tournaments/{slug}/standings", summary="The table")
def get_standings(slug: str, db: CallerDb):
    t = find(db, slug)
    seeds = _seeds(db, slug)
    players = {s.id: s.rating for s in seeds}
    results = _results(db, t["id"])
    for r in results:  # someone removed after playing still counts for others' tie-breaks
        for who in (r.white, r.black):
            if who and who not in players:
                players[who] = 0
    if t["format"] == "arena":
        lines = standings.arena(players, results)
    else:
        lines = standings.table(players, results, t["tiebreaks"])
    names = _people(db, players)
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


@router.post("/v1/tournaments/{slug}/rounds/next", summary="Pair the next round (or a knockout's tie-breaks)")
def next_round(slug: str, body: NextIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    t = find(db, slug)
    if t["status"] != "live":
        raise HTTPException(status_code=409, detail="Start the tournament before pairing.")
    if t["format"] == "arena":
        raise HTTPException(status_code=409, detail="An arena pairs players as they become free.")
    seeds = _seeds(db, slug)
    history = _results(db, t["id"])
    if any(r.result is None for r in history):
        raise HTTPException(status_code=409, detail="Games in this round are still being played.")
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
                raise pairing.CannotPair("every round has been played")
            if latest:
                order = _rr_order(history, seeds)
            else:
                order = seeds
            pairs = pairing.round_robin(order, round_no)
        else:
            round_no = latest + 1
            if t["rounds_count"] and round_no > t["rounds_count"]:
                raise pairing.CannotPair("every round has been played")
            pairs = pairing.swiss(seeds, history, round_no)
    except pairing.CannotPair as e:
        raise HTTPException(status_code=409, detail=str(e).capitalize() + ".")
    games = _publish(db, by, t, round_no, pairs, body.start)
    return {"round": round_no, "games": len(games), "started": body.start}


def _rr_order(history: list[standings.Result], seeds: list[pairing.Seed]) -> list[pairing.Seed]:
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


@router.post("/v1/rounds/{round_id}/start", summary="Start the clocks on a published round")
def start_round(round_id: str, db: UserDb):
    return one(db.rpc("start_round", {"p_round": round_id}).execute())


# -----------------------------------------------------------------------------
# Games
# -----------------------------------------------------------------------------
@router.get("/v1/games/{game_id}", summary="A game: position, clocks, moves, players")
def get_game(game_id: str, db: CallerDb):
    g = _game(db, game_id)
    moves = rows(db.table("moves").select("ply,move,san,clock_ms,created_at").eq("game_id", game_id).order("ply").execute())
    now = db.rpc("server_now", {}).execute().data
    return {"game": g, "moves": moves, "server_now": now}


@router.get("/v1/me/games", summary="Your games in progress")
def my_games(db: UserDb, authorization: Auth = None):
    me = caller_id(authorization)
    found = rows(
        db.table("games")
        .select(GAME_FULL)
        .in_("status", ["scheduled", "live"])
        .or_(f"white_id.eq.{me},black_id.eq.{me}")
        .order("created_at", desc=True)
        .limit(20)
        .execute()
    )
    return found


@router.post("/v1/games/{game_id}/move", summary="Make a move")
def make_move(game_id: str, body: MoveIn, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    g = _game(db, game_id)
    if g["status"] != "live":
        raise HTTPException(status_code=409, detail="This game is not in progress.")
    # Said plainly before judging: "e7e5 is not legal here" is true when it is
    # White's move, but "not your move" is what the player needs to hear. The
    # database checks both again.
    side = "white" if by == g["white_id"] else "black" if by == g["black_id"] else None
    if side is None:
        raise HTTPException(status_code=403, detail="You're not playing this game.")
    if side != g["turn"]:
        raise HTTPException(status_code=409, detail="It's not your move.")
    if body.ply is not None and body.ply != g["ply"]:
        raise HTTPException(status_code=409, detail="The position has moved on. Your board will catch up.")
    t = g["tournament"]
    history = _history(db, g)
    # The record and the stored position must agree before anything is built on
    # either: if they ever do not, stop rather than rule on the wrong board.
    if rules.position_after(t["game"], _variant(t), history) != g["position"]:
        raise HTTPException(status_code=500, detail="This game's record is inconsistent. An organiser has to look at it.")
    try:
        r = rules.judge(t["game"], _variant(t), history, body.move)
    except rules.Illegal as e:
        raise HTTPException(status_code=422, detail=str(e).capitalize() + ".")
    payload, sig = sign(
        "move",
        by,
        {
            "game": game_id,
            "ply": g["ply"],
            "before": g["position"],
            "move": r.move,
            "san": r.san,
            "after": r.after.position,
            "turn": r.after.turn,
            "legal": r.after.legal,
            "result": r.result,
            "termination": r.termination,
        },
    )
    return one(db.rpc("play_move", {"p_payload": payload, "p_sig": sig}).execute())


@router.post("/v1/games/{game_id}/flag", summary="Claim that the player to move is out of time")
def claim_flag(game_id: str, db: UserDb, authorization: Auth = None):
    by = caller_id(authorization)
    g = _game(db, game_id)
    if g["status"] != "live":
        raise HTTPException(status_code=409, detail="This game is not in progress.")
    t = g["tournament"]
    result = rules.flag_result(t["game"], _variant(t), _history(db, g))
    payload, sig = sign("flag", by, {"game": game_id, "ply": g["ply"], "result": result})
    return one(db.rpc("claim_flag", {"p_payload": payload, "p_sig": sig}).execute())


@router.post("/v1/games/{game_id}/resign", summary="Resign")
def resign(game_id: str, db: UserDb):
    return one(db.rpc("resign", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/draw", summary="Offer a draw, or accept the one offered")
def offer_draw(game_id: str, db: UserDb):
    return one(db.rpc("offer_draw", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/draw/decline", summary="Decline a draw offer")
def decline_draw(game_id: str, db: UserDb):
    return one(db.rpc("decline_draw", {"p_game": game_id}).execute())


@router.post("/v1/games/{game_id}/result", summary="Set or correct a result (organisers)")
def set_result(game_id: str, body: ResultIn, db: UserDb):
    return one(db.rpc("set_result", {"p_game": game_id, "p_result": body.result}).execute())


# -----------------------------------------------------------------------------
# Arena
# -----------------------------------------------------------------------------
@router.post("/v1/tournaments/{slug}/arena/join", summary="Ask for your next arena game")
def arena_join(slug: str, db: UserDb, authorization: Auth = None):
    """Queue, then try to pair at once with whoever suits best. If nobody is
    waiting, you stay queued and the next player to arrive is paired with you."""
    me = caller_id(authorization)
    t = find(db, slug)
    db.rpc("arena_join", {"p_tournament": t["id"]}).execute()
    waiting_ids = [q["user_id"] for q in rows(
        db.table("arena_queue").select("user_id,since").eq("tournament_id", t["id"]).order("since").execute()
    )]
    seeds = {s.id: s for s in _seeds(db, slug)}
    waiting = [seeds.get(i, pairing.Seed(i)) for i in waiting_ids]
    history = _results(db, t["id"])
    scores = {l.player: l.points for l in standings.arena({s.id: s.rating for s in waiting}, history)}
    pick = pairing.arena_pick(me, waiting, scores, history)
    if pick is None:
        return {"status": "waiting"}
    try:
        [game] = _publish(db, me, t, None, [pick], True)
    except Exception:
        # Someone else paired the opponent first. Still queued; the client asks again.
        return {"status": "waiting"}
    return {"status": "paired", "game": game}


@router.post("/v1/tournaments/{slug}/arena/leave", summary="Stop being paired")
def arena_leave(slug: str, db: UserDb):
    t = find(db, slug)
    db.rpc("arena_leave", {"p_tournament": t["id"]}).execute()
    return {"status": "left"}
