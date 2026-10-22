"""
Seeded randomness - every choice an agent makes can be made again.

A decision's seed is a string (game id, ply, persona version), hashed with
cyrb128 into the 128-bit state of sfc32. The same seed gives the same numbers
here, in the TypeScript the brain began as, and in a browser, which is what
lets a decision be replayed exactly ("why did it play that?").
"""

from __future__ import annotations

import math
from typing import Callable, Sequence

from agents.jsmath import M32, imul, utf16_units


def _cyrb128(s: str) -> tuple[int, int, int, int]:
    h1, h2, h3, h4 = 1779033703, 3144134277, 1013904242, 2773480762
    for k in utf16_units(s):
        h1 = h2 ^ imul(h1 ^ k, 597399067)
        h2 = h3 ^ imul(h2 ^ k, 2869860233)
        h3 = h4 ^ imul(h3 ^ k, 951274213)
        h4 = h1 ^ imul(h4 ^ k, 2716044179)
    h1 = imul(h3 ^ (h1 >> 18), 597399067)
    h2 = imul(h4 ^ (h2 >> 22), 2869860233)
    h3 = imul(h1 ^ (h3 >> 17), 951274213)
    h4 = imul(h2 ^ (h4 >> 19), 2716044179)
    h1 ^= h2 ^ h3 ^ h4
    h2 ^= h1
    h3 ^= h1
    h4 ^= h1
    return h1 & M32, h2 & M32, h3 & M32, h4 & M32


def _sfc32(a: int, b: int, c: int, d: int) -> Callable[[], float]:
    state = [a & M32, b & M32, c & M32, d & M32]

    def draw() -> float:
        a, b, c, d = state
        t = (((a + b) & M32) + d) & M32
        d = (d + 1) & M32
        a = b ^ (b >> 9)
        b = (c + (c << 3)) & M32
        c = ((c << 21) & M32) | (c >> 11)
        c = (c + t) & M32
        state[:] = [a, b, c, d]
        return t / 4294967296

    return draw


class Rng:
    """sfc32 seeded from a string; `fork` gives an independent named stream."""

    def __init__(self, seed: str):
        self.seed = seed
        self._raw = _sfc32(*_cyrb128(seed))
        # Discard the first draws: sfc32 from a fresh hash needs a few to mix.
        for _ in range(12):
            self._raw()
        self._spare: float | None = None

    def next(self) -> float:
        return self._raw()

    def chance(self, p: float) -> bool:
        return self._raw() < p

    def between(self, lo: float, hi: float) -> float:
        return lo + (hi - lo) * self._raw()

    def normal(self) -> float:
        if self._spare is not None:
            s = self._spare
            self._spare = None
            return s
        u = 0.0
        while u == 0:
            u = self._raw()
        v = self._raw()
        r = math.sqrt(-2 * math.log(u))
        self._spare = r * math.sin(2 * math.pi * v)
        return r * math.cos(2 * math.pi * v)

    def lognormal(self, median: float, sigma: float) -> float:
        return median * math.exp(sigma * self.normal())

    def weighted(self, weights: Sequence[float]) -> int:
        total = 0.0
        for w in weights:
            total += max(0.0, w)
        if total <= 0:
            return math.floor(self._raw() * len(weights))
        x = self._raw() * total
        for i, w in enumerate(weights):
            x -= max(0.0, w)
            if x < 0:
                return i
        return len(weights) - 1

    def fork(self, label: str) -> "Rng":
        return Rng(f"{self.seed}/{label}")


def rng_from(seed: str) -> Rng:
    return Rng(seed)
