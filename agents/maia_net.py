"""
Maia's policy network, run with numpy.

Maia (CSSLab, lc0 format) is small: an input convolution, six residual blocks
with squeeze-and-excitation, and a policy head of two convolutions whose 80x64
outputs are gathered into lc0's 1,858 moves. That is all the brain asks of it,
so it runs here as plain matrix products, with no inference runtime: the
agents function stays small enough to ship whole (agents/bin/README.md).

The weights are the ONNX models' own (agents/models/maia), extracted once into
agents/models/maia-npz by `python -m agents.maia_net convert`, which needs the
`onnx` package; serving needs only numpy. It reproduces onnxruntime's logits to
float rounding (tests/test_maia_net.py), the same order of difference as
onnxruntime on x86 against ARM, which left every sampled decision unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ONNX_DIR = Path(__file__).parent / "models" / "maia"
NPZ_DIR = Path(__file__).parent / "models" / "maia-npz"
BLOCKS = 6


def _conv3x3(x: np.ndarray, w: np.ndarray, b: np.ndarray) -> np.ndarray:
    """x (C, 8, 8), w as (O, C*9): a 3x3 convolution with zero padding of 1."""
    c = x.shape[0]
    padded = np.zeros((c, 10, 10), dtype=np.float32)
    padded[:, 1:9, 1:9] = x
    # Patches in (C, kh, kw) order, matching the kernel's flattening.
    patches = np.empty((c, 3, 3, 8, 8), dtype=np.float32)
    for i in range(3):
        for j in range(3):
            patches[:, i, j] = padded[:, i:i + 8, j:j + 8]
    return (w @ patches.reshape(c * 9, 64) + b[:, None]).reshape(-1, 8, 8)


class MaiaNet:
    """One rating band's network."""

    def __init__(self, weights: dict[str, np.ndarray]):
        self.w = weights

    @classmethod
    def load(cls, path: Path) -> "MaiaNet":
        with np.load(path) as z:
            return cls({k: z[k] for k in z.files})

    def policy_logits(self, planes: np.ndarray) -> np.ndarray:
        """planes (112, 8, 8) float32 -> the 1,858 policy logits."""
        w = self.w
        x = np.maximum(_conv3x3(planes, w["input.w"], w["input.b"]), 0)
        for k in range(BLOCKS):
            p = f"block{k}."
            y = np.maximum(_conv3x3(x, w[p + "conv1.w"], w[p + "conv1.b"]), 0)
            y = _conv3x3(y, w[p + "conv2.w"], w[p + "conv2.b"])
            # Squeeze and excitation: a gate and a bias per channel, from the mean.
            s = np.maximum(y.mean(axis=(1, 2)) @ w[p + "se1.w"] + w[p + "se1.b"], 0)
            s = s @ w[p + "se2.w"] + w[p + "se2.b"]
            c = y.shape[0]
            gate = 1 / (1 + np.exp(-s[:c]))
            y = gate[:, None, None] * y + s[c:][:, None, None]
            x = np.maximum(y + x, 0)
        y = np.maximum(_conv3x3(x, w["policy1.w"], w["policy1.b"]), 0)
        y = _conv3x3(y, w["policy2.w"], w["policy2.b"])
        return y.reshape(-1)[w["mapping"]]


def convert(onnx_dir: Path = ONNX_DIR, out_dir: Path = NPZ_DIR) -> list[Path]:
    """Extract each band's policy weights from its ONNX model (needs `onnx`)."""
    import onnx
    from onnx import numpy_helper

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for model in sorted(onnx_dir.glob("maia-*.onnx")):
        g = onnx.load(str(model)).graph
        t = {i.name: numpy_helper.to_array(i) for i in g.initializer}

        def kernel(name: str) -> np.ndarray:
            k = t[name].astype(np.float32)
            return np.ascontiguousarray(k.reshape(k.shape[0], -1))

        weights = {
            "input.w": kernel("/inputconv/w/kernel"),
            "input.b": t["/inputconv/w/bias"].astype(np.float32),
            "policy1.w": kernel("/policy/conv1/w/kernel"),
            "policy1.b": t["/policy/conv1/w/bias"].astype(np.float32),
            "policy2.w": kernel("/policy/conv2/w/kernel"),
            "policy2.b": t["/policy/conv2/w/bias"].astype(np.float32),
            "mapping": t["/const/mapping_table"].astype(np.int64),
        }
        for k in range(BLOCKS):
            b = f"/block{k}/"
            weights.update({
                f"block{k}.conv1.w": kernel(b + "conv1/w/kernel"),
                f"block{k}.conv1.b": t[b + "conv1/w/bias"].astype(np.float32),
                f"block{k}.conv2.w": kernel(b + "conv2/w/kernel"),
                f"block{k}.conv2.b": t[b + "conv2/w/bias"].astype(np.float32),
                f"block{k}.se1.w": t[b + "conv2/se/matmul1/w"].astype(np.float32),
                f"block{k}.se1.b": t[b + "conv2/se/add1/w"].astype(np.float32),
                f"block{k}.se2.w": t[b + "conv2/se/matmul2/w"].astype(np.float32),
                f"block{k}.se2.b": t[b + "conv2/se/add2/w"].astype(np.float32),
            })
        # The graph is fixed: anything else in it would be a different network.
        ops = {n.op_type for n in g.node}
        assert ops <= {"Conv", "Relu", "Add", "MatMul", "Reshape", "ReduceMean", "Split", "Sigmoid", "Mul",
                       "Gather", "Softmax"}, ops
        assert sum(1 for n in g.node if n.op_type == "Conv") == 1 + 2 * BLOCKS + 2 + 1, "not a 6-block Maia"
        out = out_dir / (model.stem + ".npz")
        np.savez(out, **weights)
        written.append(out)
    return written


if __name__ == "__main__":
    if sys.argv[1:] == ["convert"]:
        for p in convert():
            print(p)
    else:
        print("usage: python -m agents.maia_net convert")
