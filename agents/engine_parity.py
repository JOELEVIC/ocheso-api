"""
Do these engines see positions the way calibration's did?

Calibration v1 was fitted on analyses made by Stockfish 18 lite (WASM) and Maia
(onnxruntime-web); v2 on the same positions analysed by native Stockfish 19 and
onnxruntime (agents/calibration.py). This re-analyses held-out positions with
the engines configured here, exactly as the brain would in play (budget_for the
mover's rating, Maia for their band), replays them with the shipped priors, and
sets that beside v1 on the stored lite analyses. Run it after any engine
change: if the scores move, the priors want a re-fit for the new engine.

    python -m agents.engine_parity [positions] [samples]
"""

from __future__ import annotations

import sys
import time

from agents.chess.brain import analyse_position, budget_for
from agents.chess.priors import PRIORS, PRIORS_V1
from agents.chess.replay import replay
from agents.engines import Engines, Maia, Stockfish


def measure(positions: int = 200, samples: int = 8) -> dict:
    engines = Engines(Stockfish(), Maia())
    started = time.time()

    def analyse(row: dict):
        meta = row["meta"]
        rating = max(100, min(2600, meta["elo"]))
        # The stored analyses carry the history Maia needs; replay uses the same.
        return analyse_position(
            engines, row["analysis"]["fen"], row["analysis"]["history"], ratings=[rating], budget=budget_for(rating)
        )

    stored = replay(samples, limit=positions, priors=PRIORS_V1)
    fresh = replay(samples, analyse=analyse, limit=positions, priors=PRIORS)
    engines.stockfish.close()
    same_top = sum(
        1
        for a, b in zip(stored["moves"], fresh["moves"])
        if max(set(a), key=a.count) == max(set(b), key=b.count)
    )
    keys = ("positions", "top1", "logLik", "blunderGap")
    return {
        "stored": {k: stored[k] for k in keys},
        "fresh": {k: fresh[k] for k in keys},
        "sameMostLikelyMove": round(same_top / len(stored["moves"]), 4),
        "seconds": round(time.time() - started, 1),
        "perPositionMs": round((time.time() - started) * 1000 / positions / 2, 1),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    s = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    print(measure(n, s))
