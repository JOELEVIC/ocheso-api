"""
Maia on numpy (agents/maia_net.py) against the references it replaced.

lc0's own Maia-1500 policy on 52 positions is the standing yardstick: it needs
nothing but the repository, so it runs everywhere. Where onnxruntime is
installed (requirements-dev.txt), every band is also held to it logit by logit.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from agents.chess.maia import MAIA_PLANES, maia_history, maia_input, maia_policy
from agents.engines import Maia
from agents.maia_net import NPZ_DIR, MaiaNet

ROOT = Path(__file__).resolve().parent.parent
CONFORMANCE = json.loads((ROOT / "agents/golden/maia-conformance.json").read_text())
BANDS = range(1100, 2000, 100)


def _planes(fen: str, moves: list[str], start: str | None) -> np.ndarray:
    h = maia_history(start, moves, fen) if moves else {"fens": [fen], "fromStandardStart": False}
    return np.asarray(maia_input(h["fens"], h["fromStandardStart"]), dtype=np.float32).reshape(MAIA_PLANES, 8, 8)


def test_every_band_is_shipped():
    for band in BANDS:
        assert (NPZ_DIR / f"maia-{band}.npz").exists(), band
        assert Maia().available(band)


def test_matches_lc0s_own_maia():
    worst = 0.0
    for c in CONFORMANCE["cases"]:
        start = c["startFen"] if c["startFen"] not in (None, "None") else None
        net = MaiaNet.load(NPZ_DIR / f"maia-{int(c['band'])}.npz")
        policy = maia_policy(net.policy_logits(_planes(c["fen"], c["moves"], start)).tolist(), c["fen"])
        worst = max(worst, max(abs(policy.get(m, 0) - p) for m, p in c["lc0"].items()))
    assert worst < 0.001, worst  # lc0 rounds; the onnxruntime path agreed to the same 0.06%


def test_matches_onnxruntime_logit_for_logit():
    ort = pytest.importorskip("onnxruntime")
    fens = [(c["fen"], c["moves"], c["startFen"] if c["startFen"] not in (None, "None") else None)
            for c in CONFORMANCE["cases"][:20]]
    for band in BANDS:
        session = ort.InferenceSession(str(ROOT / f"agents/models/maia/maia-{band}.onnx"))
        net = MaiaNet.load(NPZ_DIR / f"maia-{band}.npz")
        for fen, moves, start in fens:
            planes = _planes(fen, moves, start)
            ref = session.run(["/output/policy"], {"/input/planes": planes[None]})[0][0]
            got = net.policy_logits(planes)
            assert np.abs(ref - got).max() < 1e-4, (band, fen)
            assert ref.argmax() == got.argmax(), (band, fen)
