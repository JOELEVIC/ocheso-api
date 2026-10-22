"""
The numbers that make a rating feel like a rating.

v0 was hand-set from coaching experience. v1 was fitted to people: 2,000
positions real Lichess players faced, maximising the likelihood of the move
each person played while holding blunder rates to theirs; on held-out positions
the brain's most likely move is the person's own about 46% of the time. Think
times are measured from 5.5 million rated games with clocks (think_v1.json).
Below 800 the data is thin, so the 200 knot is v0's.

v1 was fitted on what Stockfish 18 lite (WASM) and onnxruntime-web saw. The
API runs native Stockfish 19 and Maia natively (onnxruntime when v2 was fitted;
numpy since, equal to float rounding - agents/maia_net.py), which see the same positions a
little differently (sharper evaluations, so people's misjudgements need more
perception noise to reproduce). v2 is v1 re-fitted on the same positions
analysed by those engines (agents/calibration.py, the analyses in
agents/golden/native-*.jsonl.gz). Held out, at 32 samples, against the
native analyses: top-1 47.3% -> 48.4%, log-likelihood -1.930 -> -1.914,
blunder gap 2.52 -> 2.47 points. The fit no longer needs v0's 200 knot to
stay monotone, so it keeps its own.

Known gap, in both: from 1600 up it blunders too rarely - under 1% at 2000+
against people's 5-6% as Stockfish 19 judges them (mostly time scrambles). A
lapse only costs something when a refuted move looks attractive, so raising
lapse rates barely moves it; it wants a time-pressure model, not a knob.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Optional

from agents.curves import curve

THINK_V1: dict = json.loads((Path(__file__).parent.parent / "data" / "think_v1.json").read_text())


@dataclass(frozen=True)
class Priors:
    version: str
    vision_depth: Callable[[float], float]
    lapse: Callable[[float], float]
    temperature: Callable[[float], float]
    policy_weight: Callable[[float], float]
    perception_noise: Callable[[float], float]
    time_usage: Callable[[float], float]
    think_sigma: float
    expected_moves: int
    maia_floor: int
    maia_ceiling: int
    think: Optional[dict] = None


PRIORS_V0 = Priors(
    version="v0-hand",
    vision_depth=curve([[200, 1], [600, 2], [1000, 3], [1400, 4.5], [1800, 6.5], [2200, 8.5], [2600, 10]]),
    lapse=curve([[200, 0.42], [600, 0.25], [1000, 0.13], [1400, 0.065], [1800, 0.028], [2200, 0.011], [2600, 0.004]]),
    temperature=curve([[200, 16], [600, 11], [1000, 7.5], [1400, 5], [1800, 3.2], [2200, 2], [2600, 1.2]]),
    policy_weight=curve([[200, 7], [1000, 5], [1400, 4], [1800, 3], [2200, 2], [2600, 1.2]]),
    perception_noise=curve([[200, 9], [600, 7], [1000, 5], [1400, 3.5], [1800, 2.2], [2200, 1.4], [2600, 0.8]]),
    time_usage=curve([[200, 0.3], [800, 0.48], [1400, 0.6], [2000, 0.7], [2600, 0.75]]),
    think_sigma=0.7,
    expected_moves=40,
    maia_floor=1100,
    maia_ceiling=1900,
)

PRIORS_V1 = replace(
    PRIORS_V0,
    version="v1-lichess-2026-09",
    vision_depth=curve([[200, 1], [600, 2.4], [1000, 3.8], [1400, 5.3], [1800, 7.3], [2200, 9.3], [2600, 10.8]]),
    lapse=curve([[200, 0.42], [600, 0.38], [1000, 0.214], [1400, 0.088], [1800, 0.031], [2200, 0.01], [2600, 0.003]]),
    temperature=curve([[200, 16], [600, 6.5], [1000, 2.259], [1400, 2.434], [1800, 2.517], [2200, 2.542], [2600, 2.465]]),
    policy_weight=curve([[200, 7], [600, 6], [1000, 5], [1400, 4], [1800, 3], [2200, 2], [2600, 1.2]]),
    perception_noise=curve([[200, 9], [600, 5.8], [1000, 3.352], [1400, 2.346], [1800, 1.475], [2200, 0.938], [2600, 0.536]]),
    think=THINK_V1,
)

PRIORS_V2 = replace(
    PRIORS_V1,
    version="v2-native-sf19-2026-10",
    lapse=curve([[200, 0.42], [600, 0.38], [1000, 0.214], [1400, 0.088], [1800, 0.031], [2200, 0.015], [2600, 0.006]]),
    temperature=curve([[200, 6.376], [600, 3.04], [1000, 1.24], [1400, 1.568], [1800, 1.902], [2200, 2.255], [2600, 2.566]]),
    policy_weight=curve([[200, 13.544], [600, 10.716], [1000, 8.244], [1400, 6.088], [1800, 4.215], [2200, 2.594], [2600, 1.437]]),
    perception_noise=curve([[200, 20.03], [600, 12.908], [1000, 7.46], [1400, 5.221], [1800, 3.283], [2200, 2.088], [2600, 1.193]]),
)

# The calibration agents play with now. It belongs to the engines in
# agents/engines.py: analyses from other engines want their own fit.
PRIORS = PRIORS_V2
