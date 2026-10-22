"""
Deciding a move the way a person does.

Given the engine's table for a position, a persona and its mood, `decide` is
pure: the same analysis and seed give the same move and the same think time,
which is what lets any move be replayed and the difficulty gauge sample
thousands of "people" from one analysis.

  1. Book first, while the game is in the persona's repertoire.
  2. Think time: how long this person spends here.
  3. Vision from that time: rushed people see less.
  4. Each candidate is judged as this person would see it - at their vision
     depth, or, when they overlook the reply (a lapse), by the material on the
     board after the move alone. Lapses are likelier when the reply is the kind
     people miss: quiet, backward, long-range, a knight's.
  5. Style bends the judgement; the human prior (what people at this level play
     here) weighs in; a softmax with a rating-set temperature picks.
  6. Sometimes they check the chosen move once more and change their mind.

Nothing is "injected": an 800's mistakes come from shallow vision, lapses and a
wide temperature, which is why they look like an 800's mistakes.
"""

from __future__ import annotations

import math
from typing import Optional

from agents.chess.analysis import MATE_CP, Analysis, cp_at, cp_truth, pct_of_cp, ranked
from agents.chess.board import Position, move_facts, position_facts, reply_traits
from agents.chess.intuition import book_move, prior_for
from agents.chess.priors import Priors
from agents.curves import trait_factor
from agents.jsmath import clamp
from agents.rng import Rng
from agents.think_time import think_time


def effective_rating(p: dict, mood: dict, pos: dict, own_move: int) -> float:
    """The rating it plays this position at: base, today's form, and the phase it's in."""
    s = p["play"]["strength"]
    if own_move < 10 and pos["phase"] < 0.35:
        phase = s["opening"]
    elif pos["phase"] > 0.7:
        phase = s["endgame"]
    else:
        phase = s["middlegame"]
    return clamp(p["rating"] + phase + mood["form"], 100, 2900)


def character(a: Analysis, facts: dict[str, dict]) -> dict:
    """How the position reads: complexity and criticality, 0-1."""
    r = ranked(a)
    best = r[0] if r else None
    second = r[1] if len(r) > 1 else None
    if best and second:
        criticality = clamp((best["pct"] - second["pct"]) / 30, 0, 1)
    else:
        criticality = 1 if len(r) == 1 else 0
    good = len([m for m in r if best["pct"] - m["pct"] <= 4]) if best else 0
    volatility = 0.0
    if best:
        shallow = cp_at(a.moves[best["move"]], 2)
        if shallow is not None:
            volatility = clamp(abs(best["pct"] - pct_of_cp(shallow)) / 20, 0, 1)
    tactical = sum(1 for f in facts.values() if "captured" in f or f["isCheck"])
    scarcity = 1 if good <= 1 else 0.5 if good <= 3 else 0
    complexity = clamp(0.4 * volatility + 0.3 * scarcity + 0.3 * min(1, tactical / 8), 0, 1)
    return {"criticality": criticality, "complexity": complexity, "bestPct": best["pct"] if best else 50, "goodMoves": good}


def style_bonus(p: dict, f: dict, pos: dict, perceived_root_pct: float) -> float:
    """How this persona's taste bends a move's appeal, in win-% points."""
    s = p["play"]["style"]

    def c(t: float) -> float:
        return (t - 0.5) * 2  # -1 ... +1

    b = 0.0
    aggression = c(s["aggression"])
    if f["isCheck"]:
        b += 2.5 * aggression
    if f["nearEnemyKing"]:
        b += 1.5 * aggression
    if "captured" in f:
        b += 0.5 * aggression
    if f["naiveGain"] > 0:
        b += 1.5 * c(s["materialism"]) * min(f["naiveGain"], 3)
    ahead = perceived_root_pct > 65
    behind = perceived_root_pct < 35
    if f["isEvenTrade"]:
        if ahead:
            b += 3 * c(s["simplifyWhenAhead"])
        else:
            b -= 2 * c(s["complication"])
        if f["piece"] == "b":
            b -= 2 * c(s["bishops"])
        if f["piece"] == "n":
            b += 2 * c(s["bishops"])
    if behind and (f["isCheck"] or f["nearEnemyKing"] or f["makesThreat"]):
        b += 2 * c(s["riskWhenBehind"])
    if ahead and (f["isCheck"] or f["nearEnemyKing"]):
        b += 1.5 * c(s["riskWhenAhead"])
    if f["isCastle"]:
        b += 3 * c(s["kingSafety"])
    if f["weakensOwnKing"]:
        b -= 2.5 * c(s["kingSafety"])
    if f["isPawnStorm"] and pos["phase"] < 0.7:
        b += 2 * c(s["pawnStorm"])
    if f["makesThreat"]:
        b += 2.5 * c(s["hopeChess"])
    return b


def _softmax(utilities: list[float], temperature: float) -> list[float]:
    top = max(utilities)
    exps = [math.exp((u - top) / temperature) for u in utilities]
    total = sum(exps)
    return [e / total for e in exps]


def decide(
    a: Analysis,
    *,
    persona: dict,
    priors: Priors,
    mood: dict,
    rng: Rng,
    own_move: int,
    clock_ms: float,
    cadence: dict,
    from_start: bool,
    prev_fen: Optional[str] = None,
    first_move_cap_ms: Optional[float] = None,
) -> dict:
    p = persona
    pos = Position(a.fen, a.history, prev_fen)
    pos_facts = position_facts(pos)
    facts = move_facts(pos)
    if not facts:
        raise ValueError("no legal moves")
    rating = effective_rating(p, mood, pos_facts, own_move)
    tags: list[str] = []

    def truth_of(m: str) -> Optional[float]:
        e = a.moves.get(m)
        cp = cp_truth(e) if e else None
        return None if cp is None else pct_of_cp(cp)

    ranking = ranked(a)
    best = ranking[0] if ranking else None

    def loss_of(m: str) -> float:
        t = truth_of(m)
        return max(0, best["pct"] - t) if best and t is not None else 0

    shape = character(a, facts)

    # 1. Book.
    from_book = book_move(p, a.history, own_move, rng.fork("book")) if from_start else None
    book = from_book is not None and from_book in facts

    # 2. Time. How obvious the best move is to this person shortens it.
    prior, source = prior_for(rating, priors, pos_facts, facts, a.policy)
    obviousness = clamp(prior.get(best["move"], 0) * 2.5, 0, 1) if best else 0
    think = think_time(
        {
            "rating": rating,
            "cadence": cadence,
            "ownMove": own_move,
            "clockMs": clock_ms,
            "complexity": shape["complexity"] * (1 - 0.7 * obviousness),
            "criticality": shape["criticality"] * (1 - obviousness),
            "onlyMove": pos_facts["onlyMove"],
            "recapture": any(f["isRecapture"] for f in facts.values()) and pos_facts["lastCaptureSquare"] is not None,
            "inCheck": pos_facts["inCheck"],
            "book": book,
            "evalPct": shape["bestPct"],
            "firstMoveCapMs": first_move_cap_ms,
        },
        p,
        mood,
        priors,
        rng.fork("time"),
    )
    tags.extend(think["tags"])

    if book:
        f = facts[from_book]
        t = truth_of(f["uci"])
        return {
            "move": f["uci"],
            "san": f["san"],
            "thinkMs": think["ms"],
            "medianMs": think["medianMs"],
            "visionDepth": 0,
            "book": True,
            "lossPct": loss_of(f["uci"]),
            "evalPct": t if t is not None else shape["bestPct"],
            "effectiveRating": rating,
            "priorSource": "heuristic",
            "candidates": [],
            "tags": [*tags, "book"],
        }

    # 3. Vision from time.
    trouble = "time-trouble" in think["tags"]
    time_factor = clamp(math.log2(max(1, think["ms"]) / max(1, think["medianMs"])), -1.5, 1.5)
    raw_depth = (
        priors.vision_depth(rating)
        + (p["play"]["strength"]["vision"] - 0.5) * 3
        + time_factor
        - 1.5 * mood["tilt"]
        - 0.8 * mood["fatigue"]
        - (1.5 * p["clock"]["panic"] if trouble else 0)
    )
    extra = 1 if rng.fork("vision").chance(raw_depth - math.floor(raw_depth)) else 0
    vision = clamp(math.floor(raw_depth) + extra, 1, max(1, a.max_depth))

    # 4. Candidates, as this person sees them.
    by_prior = sorted([(m, pr) for m, pr in prior.items() if m in facts], key=lambda x: -x[1])
    by_truth = [r for r in ranked(a) if r["move"] in facts]
    pool: dict[str, None] = {}
    for m, pr in by_prior:
        if len(pool) < 10 and pr >= 0.015:
            pool[m] = None
    for r in by_truth[:5]:
        pool[r["move"]] = None
    if not pool:
        pool[by_prior[0][0]] = None

    # What the position is worth to this person before any capture they might
    # make: the best move's value at their depth, less what that move itself
    # takes. A move whose reply they overlook looks this good, plus its own
    # capture - never the value another move's capture would bring.
    root_cp = -math.inf
    for e in a.moves.values():
        cp = cp_at(e, vision)
        if cp is None:
            continue
        own = cp - 100 * (facts[e.move]["naiveGain"] if e.move in facts else 0)
        if own > root_cp:
            root_cp = own
    if not math.isfinite(root_cp):
        root_cp = 0
    root_pct = pct_of_cp(root_cp)

    lapse_base = priors.lapse(rating) * trait_factor(1 - p["play"]["strength"]["attention"], 3)
    lapse_time = (1 - 0.4 * time_factor if time_factor < 0 else 1) * (1 + p["clock"]["panic"] if trouble else 1)
    lapse_mood = 1 + 0.6 * mood["tilt"] + 0.5 * p["temperament"]["overconfidence"] * max(0, mood["confidence"])
    noise = priors.perception_noise(rating)
    prng = rng.fork("perceive")

    # A person notices a threat or doesn't - once. Every candidate refuted by
    # the same reply shares one draw.
    noticed: dict[str, bool] = {}

    def overlooks(reply: str, mult: float) -> bool:
        if reply not in noticed:
            lapse_p = clamp(lapse_base * lapse_time * lapse_mood * mult, 0, 0.9)
            noticed[reply] = not prng.chance(lapse_p)
        return not noticed[reply]

    candidates: list[dict] = []
    for move in pool:
        f = facts[move]
        entry = a.moves.get(move)
        lapsed = False
        if entry and entry.reply:
            mult = 1.0
            rt = reply_traits(pos, move, entry.reply)
            if rt:
                if rt["quiet"]:
                    mult *= 1.6
                if rt["backward"]:
                    mult *= 1.6
                if rt["longRange"]:
                    mult *= 1.4
                if rt["knight"]:
                    mult *= 1.3
                if rt["check"]:
                    mult *= 0.8
            lapsed = overlooks(entry.reply, mult)
        seen_cp = cp_at(entry, vision) if entry else None
        naive_cp = 9999 if f["isMate"] else root_cp + 100 * f["naiveGain"] * (0.7 + 0.6 * p["play"]["style"]["materialism"])
        # Overlooking a reply can only make a move look better than it is.
        if seen_cp is None:
            judged_cp = naive_cp
        elif lapsed:
            judged_cp = max(seen_cp, naive_cp)
        else:
            judged_cp = seen_cp
        perceived = clamp(pct_of_cp(judged_cp) + noise * prng.normal(), 0, 100)
        style = style_bonus(p, f, pos_facts, root_pct)
        # A mate someone has seen pulls at them like nothing else on the board -
        # the shorter, the harder.
        mate_in = math.ceil((MATE_CP - judged_cp) / 2) if judged_cp >= MATE_CP - 500 else 0
        mate_seen = max(2, 16 - 4 * (mate_in - 1)) if mate_in > 0 else 0
        pr = prior.get(move, 0.001)
        candidates.append(
            {
                "move": move,
                "san": f["san"],
                "prior": pr,
                "perceivedPct": perceived,
                "truthPct": truth_of(move),
                "style": style,
                "utility": perceived + mate_seen + priors.policy_weight(rating) * math.log(pr + 0.003) + style,
                "p": 0,
                "lapsed": lapsed,
                "depthSeen": 0 if lapsed else vision,
            }
        )

    # 5. Choose.
    s = p["play"]["style"]
    temperature = priors.temperature(rating)
    if root_pct < 35:
        temperature *= 1 + 0.6 * (s["riskWhenBehind"] - 0.5) - 0.4 * (p["temperament"]["tenacity"] - 0.5)
    if trouble:
        temperature *= 1 + 0.8 * p["clock"]["panic"]
    temperature *= 1 + 0.6 * mood["tilt"]
    probs = _softmax([c["utility"] for c in candidates], temperature)
    for c, pr in zip(candidates, probs):
        c["p"] = pr
    crng = rng.fork("choose")
    chosen = candidates[crng.weighted(probs)]

    # 6. One more look.
    check_chance = (0.1 + 0.6 * p["play"]["strength"]["blunderCheck"]) * (1 if think["ms"] >= think["medianMs"] * 0.8 else 0.4)
    if len(candidates) > 1 and crng.chance(check_chance):
        entry = a.moves.get(chosen["move"])
        deeper = cp_at(entry, vision + 1) if entry else None
        if deeper is not None and pct_of_cp(deeper) < chosen["perceivedPct"] - 10:
            rest = [c for c in candidates if c is not chosen]
            rest_probs = _softmax([c["utility"] for c in rest], temperature)
            chosen = rest[crng.weighted(rest_probs)]
            tags.append("changed-mind")
        else:
            tags.append("double-checked")
    if chosen["lapsed"]:
        tags.append("overlooked-reply")

    return {
        "move": chosen["move"],
        "san": chosen["san"],
        "thinkMs": think["ms"],
        "medianMs": think["medianMs"],
        "visionDepth": vision,
        "book": False,
        "lossPct": loss_of(chosen["move"]),
        "evalPct": chosen["truthPct"] if chosen["truthPct"] is not None else chosen["perceivedPct"],
        "effectiveRating": rating,
        "priorSource": source,
        "candidates": sorted(candidates, key=lambda c: -c["p"]),
        "tags": tags,
    }
