"""
Calibration regression: how human the brain is on positions real people faced.

The held-out half of the 2,003 positions calibration v1 was fitted on, each
decided by a typical person at the mover's rating. Scores: how often the
brain's most likely move is the person's own (top1), the log-likelihood of the
move they played, and how far the brain's blunder rate is from theirs per
rating band. The stored analyses make it engine-free; `analyse` replaces them
with fresh ones to measure an engine (agents/engines.py) against calibration.
"""

from __future__ import annotations

import gzip
import json
import math
from pathlib import Path
from typing import Callable, Optional

from agents.chess.analysis import Analysis, from_snapshot, ranked
from agents.chess.decide import decide
from agents.chess.persona import persona
from agents.chess.priors import PRIORS, Priors
from agents.mood import start_game
from agents.persona import parse_cadence
from agents.rng import rng_from

ANALYSED = Path(__file__).parent.parent / "golden" / "analysed.jsonl.gz"


def rows(path: Path = ANALYSED) -> list[dict]:
    with gzip.open(path, "rt") as f:
        return [json.loads(line) for line in f if line.strip()]


def _cadence(tc: str) -> dict:
    base, inc = tc.split("+")
    return parse_cadence(f"{int(base) // 60 if int(base) % 60 == 0 else int(base) / 60}+{inc}")


def held_out(source: Optional[list[dict]] = None) -> list[dict]:
    """The half calibration never fitted on: every second position."""
    return [r for i, r in enumerate(source if source is not None else rows()) if i % 2 == 1]


def replay(samples: int = 8, analyse: Optional[Callable[[dict], Analysis]] = None,
           limit: Optional[int] = None, priors: Priors = PRIORS,
           positions: Optional[list[dict]] = None) -> dict:
    """Scores on `positions` (default: the held-out half of the stored analyses)."""
    held_out_rows = positions if positions is not None else held_out()
    if limit:
        held_out_rows = held_out_rows[:limit]
    by_band: dict[str, dict] = {}
    top1 = 0
    log_lik = 0.0
    per_row = []
    for row in held_out_rows:
        meta = row["meta"]
        a = analyse(row) if analyse else from_snapshot(row["analysis"])
        r = ranked(a)
        best = r[0]["pct"] if r else 50
        played = next((m for m in r if m["move"] == meta["played"]), None)
        played_loss = max(0, best - (played["pct"] if played else best))
        p = persona({"rating": max(100, min(2600, meta["elo"]))})
        counts: dict[str, int] = {}
        blunders = 0
        moves = []
        for i in range(samples):
            rng = rng_from(f"{meta['fen']}/{meta['played']}/{i}")
            d = decide(
                a,
                persona=p,
                priors=priors,
                mood=start_game(p, 0, meta["elo"], rng.fork("mood")),
                rng=rng,
                own_move=int(meta["fen"].split(" ")[5] if len(meta["fen"].split(" ")) > 5 else 1) - 1,
                clock_ms=meta["clockBefore"] * 1000,
                cadence=_cadence(meta["tc"]),
                from_start=False,
            )
            moves.append(d["move"])
            counts[d["move"]] = counts.get(d["move"], 0) + 1
            if d["lossPct"] >= 20:
                blunders += 1
        per_row.append(moves)
        top = sorted(counts.items(), key=lambda kv: -kv[1])[0][0] if counts else None
        p_played = (counts.get(meta["played"], 0) + 0.5) / (samples + 0.5 * max(1, len(a.moves)))
        band = str((meta["elo"] // 400) * 400)
        cell = by_band.setdefault(band, {"n": 0, "top1": 0, "blunderModel": 0.0, "blunderReal": 0})
        cell["n"] += 1
        cell["top1"] += 1 if top == meta["played"] else 0
        cell["blunderModel"] += blunders / samples
        cell["blunderReal"] += 1 if played_loss >= 20 else 0
        top1 += 1 if top == meta["played"] else 0
        log_lik += math.log(p_played)
    gap = sum(abs(c["blunderModel"] - c["blunderReal"]) / c["n"] for c in by_band.values())

    def rnd(x: float) -> float:
        return math.floor(x * 10_000 + 0.5) / 10_000

    return {
        "positions": len(held_out_rows),
        "samples": samples,
        "top1": rnd(top1 / len(held_out_rows)),
        "logLik": rnd(log_lik / len(held_out_rows)),
        "blunderGap": rnd(gap / len(by_band)),
        "moves": per_row,
        "byBand": by_band,
    }
