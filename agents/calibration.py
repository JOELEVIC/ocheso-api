"""
Calibration: analyse positions people faced with the runtime's engines, and fit
the brain's rating curves to what those people played.

    python -m agents.calibration analyse <out.jsonl.gz> [train|held-out]
    python -m agents.calibration fit <train.jsonl.gz> <held-out.jsonl.gz> [--samples 32] [--rounds 2]

The positions are calibration v1's 2,003 (agents/golden/analysed.jsonl.gz:
real Lichess moves, the mover's rating, clock and cadence). `analyse` re-asks
the engines here about each one exactly as the brain does in play. `fit` is
fit-humanness (cca/tools/house-data) on those analyses: the typical person at
the mover's rating decides each position many times, scored on the
log-likelihood of the move really played, with blunder rates (a move losing
20+ win-% points) held to people's per rating band. Coordinate search on the
even half; the odd half is the held-out score.

Unlike v1 it starts from PRIORS_V1, not v0, and has one more knob: extra
lapses above 1800, where v1 blunders well under people's rate. Vision depth is
not fitted - it also sizes the engine budget, so changing it would change the
analyses being fitted on.
"""

from __future__ import annotations

import gzip
import json
import math
import multiprocessing as mp
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional

from agents.chess.analysis import Analysis, from_snapshot, ranked, snapshot
from agents.chess.board import set_board_memo_size
from agents.chess.decide import decide
from agents.chess.persona import persona
from agents.chess.priors import PRIORS_V1, Priors
from agents.curves import curve
from agents.jsmath import clamp
from agents.mood import start_game
from agents.persona import parse_cadence
from agents.rng import rng_from

KNOTS_AT = [200, 600, 1000, 1400, 1800, 2200, 2600]
ZERO = {"lapse0": 0.0, "lapse1": 0.0, "lapseHigh": 0.0, "temp0": 0.0, "temp1": 0.0,
        "policy0": 0.0, "policy1": 0.0, "noise0": 0.0}
STEPS = {"lapse0": 0.5, "lapse1": 0.5, "lapseHigh": 0.5, "temp0": 0.4, "temp1": 0.4,
         "policy0": 0.4, "policy1": 0.4, "noise0": 0.4}


# -----------------------------------------------------------------------------
# Analysing
# -----------------------------------------------------------------------------
def analyse(out: str, half: str = "train") -> None:
    from agents.chess.brain import analyse_position, budget_for
    from agents.chess.replay import rows
    from agents.engines import Engines, Maia, Stockfish

    engines = Engines(Stockfish(), Maia())
    parity = 0 if half == "train" else 1
    todo = [r for i, r in enumerate(rows()) if i % 2 == parity]
    started = time.time()
    with gzip.open(out, "wt") as f:
        for n, r in enumerate(todo, 1):
            rating = max(100, min(2600, r["meta"]["elo"]))
            a = analyse_position(engines, r["analysis"]["fen"], r["analysis"]["history"],
                                 ratings=[rating], budget=budget_for(rating, PRIORS_V1))
            f.write(json.dumps({"meta": r["meta"], "analysis": snapshot(a)}) + "\n")
            if n % 100 == 0:
                print(f"{n}/{len(todo)}  {time.time() - started:.0f}s", file=sys.stderr)
    engines.stockfish.close()


# -----------------------------------------------------------------------------
# Scoring
# -----------------------------------------------------------------------------
def priors_for(t: dict, base: Priors = PRIORS_V1) -> Priors:
    def x(r: float) -> float:
        return (r - 1500) / 1000

    def high(r: float) -> float:
        return max(0.0, (r - 1800) / 800)

    return replace(
        base,
        version="fit",
        lapse=lambda r: clamp(base.lapse(r) * math.exp(t["lapse0"] + t["lapse1"] * x(r) + t["lapseHigh"] * high(r)), 0, 0.9),
        temperature=lambda r: base.temperature(r) * math.exp(t["temp0"] + t["temp1"] * x(r)),
        policy_weight=lambda r: base.policy_weight(r) * math.exp(t["policy0"] + t["policy1"] * x(r)),
        perception_noise=lambda r: base.perception_noise(r) * math.exp(t["noise0"]),
    )


def as_knots(priors: Priors, base: Priors = PRIORS_V1, version: str = "fit-knots") -> Priors:
    """What ships: the fitted curves read at the knots. Below 800 the data is
    thin, so the 200 knot stays the base's."""

    def knots(f, b):
        return curve([[r, b(r) if r == 200 else math.floor(f(r) * 1000 + 0.5) / 1000] for r in KNOTS_AT])

    return replace(
        priors,
        version=version,
        lapse=knots(priors.lapse, base.lapse),
        temperature=knots(priors.temperature, base.temperature),
        policy_weight=knots(priors.policy_weight, base.policy_weight),
        perception_noise=knots(priors.perception_noise, base.perception_noise),
    )


_ITEMS: list[dict] = []


def _load(path: str) -> list[dict]:
    items = []
    with gzip.open(path, "rt") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            a: Analysis = from_snapshot(row["analysis"])
            r = ranked(a)
            best = r[0]["pct"] if r else 50
            played = next((m["pct"] for m in r if m["move"] == row["meta"]["played"]), best)
            fen = row["meta"]["fen"].split(" ")
            items.append({
                "meta": row["meta"],
                "analysis": a,
                "playedLoss": max(0, best - played),
                "ownMove": int(fen[5] if len(fen) > 5 else 1) - 1,
            })
    return items


def _cadence(tc: str) -> dict:
    base, inc = tc.split("+")
    return parse_cadence(f"{int(base) // 60 if int(base) % 60 == 0 else int(base) / 60}+{inc}")


def priors_from_knots(knots: dict, base: Priors = PRIORS_V1, version: str = "knots") -> Priors:
    return replace(base, version=version, **{name: curve(k) for name, k in knots.items()})


def _priors_of(spec: dict) -> Priors:
    if "knots" in spec:
        return priors_from_knots(spec["knots"])
    priors = priors_for(spec["theta"])
    return as_knots(priors) if spec.get("knotted") else priors


def _score_chunk(job: tuple) -> dict:
    spec, lo, hi, samples = job
    priors = _priors_of(spec)
    by_band: dict[str, dict] = {}
    for it in _ITEMS[lo:hi]:
        meta, a = it["meta"], it["analysis"]
        p = persona({"rating": max(100, min(2600, meta["elo"]))})
        counts: dict[str, int] = {}
        blunders = 0
        for i in range(samples):
            rng = rng_from(f"{meta['fen']}/{meta['played']}/{i}")
            d = decide(a, persona=p, priors=priors, mood=start_game(p, 0, meta["elo"], rng.fork("mood")), rng=rng,
                       own_move=it["ownMove"], clock_ms=meta["clockBefore"] * 1000, cadence=_cadence(meta["tc"]),
                       from_start=False)
            counts[d["move"]] = counts.get(d["move"], 0) + 1
            if d["lossPct"] >= 20:
                blunders += 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[0][0] if counts else None
        p_played = (counts.get(meta["played"], 0) + 0.5) / (samples + 0.5 * max(1, len(a.moves)))
        band = str((meta["elo"] // 400) * 400)
        b = by_band.setdefault(band, {"n": 0, "logLik": 0.0, "top1": 0, "blunderModel": 0.0, "blunderReal": 0})
        b["n"] += 1
        b["logLik"] += math.log(p_played)
        b["top1"] += 1 if top == meta["played"] else 0
        b["blunderModel"] += blunders / samples
        b["blunderReal"] += 1 if it["playedLoss"] >= 20 else 0
    return by_band


class Scorer:
    """Scores a parameter set on one position file, in parallel."""

    def __init__(self, path: str, samples: int, workers: Optional[int] = None):
        global _ITEMS
        _ITEMS = _load(path)
        self.n = len(_ITEMS)
        self.samples = samples
        workers = workers or max(1, mp.cpu_count() - 2)
        # fork: the workers share the loaded analyses.
        self.pool = mp.get_context("fork").Pool(workers, initializer=set_board_memo_size, initargs=(50_000,))
        self.chunks = [(i, min(self.n, i + 25)) for i in range(0, self.n, 25)]

    def score(self, theta: Optional[dict] = None, knotted: bool = False, knots: Optional[dict] = None) -> dict:
        spec = {"knots": knots} if knots is not None else {"theta": theta, "knotted": knotted}
        parts = self.pool.map(_score_chunk, [(spec, lo, hi, self.samples) for lo, hi in self.chunks])
        by_band: dict[str, dict] = {}
        for part in parts:
            for band, c in part.items():
                b = by_band.setdefault(band, {"n": 0, "logLik": 0.0, "top1": 0, "blunderModel": 0.0, "blunderReal": 0})
                for k in b:
                    b[k] += c[k]
        n = sum(b["n"] for b in by_band.values())
        gap = sum(abs(b["blunderModel"] - b["blunderReal"]) / b["n"] for b in by_band.values()) / len(by_band)
        out = {"logLik": sum(b["logLik"] for b in by_band.values()) / n,
               "top1": sum(b["top1"] for b in by_band.values()) / n, "blunderGap": gap, "byBand": {}}
        for band in sorted(by_band, key=int):
            b = by_band[band]
            out["byBand"][band] = {"n": b["n"], "logLik": round(b["logLik"] / b["n"], 4), "top1": round(b["top1"] / b["n"], 4),
                                   "blunderModel": round(b["blunderModel"] / b["n"], 4),
                                   "blunderReal": round(b["blunderReal"] / b["n"], 4)}
        return out

    def close(self) -> None:
        self.pool.close()


def objective(s: dict) -> float:
    """What's maximised: human likelihood, with blunder rates held to people's."""
    return s["logLik"] - 2 * s["blunderGap"]


def brief(s: dict) -> str:
    return f"logLik {s['logLik']:.4f}  top-1 {s['top1'] * 100:.1f}%  blunder gap {s['blunderGap'] * 100:.2f} pts"


def fit(train_path: str, test_path: str, samples: int = 32, rounds: int = 2) -> dict:
    train = Scorer(train_path, samples)
    theta = dict(ZERO)
    best = objective(train.score(theta))
    print(f"start (train): objective {best:.4f}", file=sys.stderr)
    steps = dict(STEPS)
    for _ in range(rounds):
        for k in steps:
            for direction in (1, -1):
                moved = False
                for _tries in range(3):
                    nxt = {**theta, k: theta[k] + direction * steps[k]}
                    o = objective(train.score(nxt))
                    if o > best + 1e-4:
                        best, theta, moved = o, nxt, True
                        print(f"  {k} {'+' if direction > 0 else '-'} -> objective {o:.4f}  {json.dumps(theta)}",
                              file=sys.stderr)
                    else:
                        break
                if moved:
                    break
            steps[k] /= 2
    train.close()

    test = Scorer(test_path, samples)
    before = test.score(ZERO)
    fitted = test.score(theta)
    shipped = test.score(theta, knotted=True)
    test.close()
    print(f"v1 held-out:     {brief(before)}", file=sys.stderr)
    print(f"fit held-out:    {brief(fitted)}", file=sys.stderr)
    print(f"knots held-out:  {brief(shipped)}", file=sys.stderr)
    p = as_knots(priors_for(theta))
    return {
        "positions": {"train": train.n, "heldOut": test.n},
        "samples": samples,
        "theta": theta,
        "heldOut": {"v1": before, "fit": fitted, "knots": shipped},
        "knots": {name: [[r, getattr(p, name)(r)] for r in KNOTS_AT]
                  for name in ("lapse", "temperature", "policy_weight", "perception_noise")},
    }


if __name__ == "__main__":
    args = sys.argv[1:]

    def opt(name: str, default: str) -> str:
        return args[args.index(name) + 1] if name in args else default

    if args and args[0] == "analyse":
        analyse(args[1], args[2] if len(args) > 2 else "train")
    elif args and args[0] == "fit":
        result = fit(args[1], args[2], int(opt("--samples", "32")), int(opt("--rounds", "2")))
        print(json.dumps(result, indent=1))
    else:
        print(__doc__)
