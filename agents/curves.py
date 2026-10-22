"""
Rating curves - how a quantity changes with playing strength.

Every rating-dependent number in the brain is a piecewise-linear curve through
knots, so calibration replaces knots without touching the code that reads them.
"""

from __future__ import annotations

from typing import Callable, Sequence

from agents.jsmath import clamp  # noqa: F401  (re-exported for the brain)

Knots = Sequence[Sequence[float]]


def curve(knots: Knots) -> Callable[[float], float]:
    """The curve through these knots (sorted by x), flat beyond the ends."""

    def at(x: float) -> float:
        if x <= knots[0][0]:
            return knots[0][1]
        last = knots[-1]
        if x >= last[0]:
            return last[1]
        for i in range(1, len(knots)):
            x1, y1 = knots[i]
            if x <= x1:
                x0, y0 = knots[i - 1]
                return y0 + ((y1 - y0) * (x - x0)) / (x1 - x0)
        return last[1]

    at.knots = [tuple(k) for k in knots]  # type: ignore[attr-defined]
    return at


def trait_factor(trait: float, span: float) -> float:
    """A 0..1 trait read as a multiplier: 0.5 -> 1, 0 -> 1/span, 1 -> span."""
    return span ** (2 * trait - 1)
