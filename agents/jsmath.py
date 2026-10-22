"""
JavaScript's arithmetic, where it differs from Python's.

The brain was written and calibrated in TypeScript; this port is held to the
TypeScript's decisions exactly (agents/golden), so every place JavaScript
rounds, truncates or wraps differently from Python goes through here rather
than being remembered at each call site.
"""

from __future__ import annotations

import math

M32 = 0xFFFFFFFF


def js_round(x: float) -> int:
    """Math.round: halves go up (towards +infinity), not to even."""
    return math.floor(x + 0.5)


def imul(a: int, b: int) -> int:
    """Math.imul, kept as an unsigned 32-bit value (the bits are what matter)."""
    return ((a & M32) * (b & M32)) & M32


def u32(x: int) -> int:
    return x & M32


def utf16_units(s: str) -> list[int]:
    """String.prototype.charCodeAt over a whole string: UTF-16 code units."""
    data = s.encode("utf-16-le")
    return [data[i] | (data[i + 1] << 8) for i in range(0, len(data), 2)]


def clamp(x: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, x))
