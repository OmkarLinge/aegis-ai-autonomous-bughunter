"""
Aegis AI — Request Jitter Engine

Adds controlled randomness to request timing so that the traffic
pattern does not look like an automated scan to pattern-based WAFs.

The jitter value is drawn from a uniform distribution:

    actual_delay = base_delay + random(0, jitter_range)

Optionally, burst jitter can inject occasional longer pauses
that mimic human "thinking" time.
"""
from __future__ import annotations

import random
import asyncio
from dataclasses import dataclass

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))
from utils.logger import get_logger

logger = get_logger(__name__, "JITTER")


@dataclass
class JitterStats:
    """Accumulated jitter statistics."""
    total_jitter_applied_s: float = 0.0
    total_calls: int = 0
    avg_jitter_s: float = 0.0
    burst_pauses: int = 0


class RequestJitter:
    """
    Randomises request timing to evade pattern-detection WAFs.

    Parameters
    ----------
    enabled : bool
        Master switch — when False, ``apply()`` is a no-op.
    jitter_range : float
        Upper bound for uniform random jitter in seconds (default 0.5).
    burst_probability : float
        Chance (0–1) that any given request gets an extra "human-like"
        pause of 1–3 seconds (default 0.05 = 5 %).
    burst_min : float
        Minimum burst pause in seconds (default 1.0).
    burst_max : float
        Maximum burst pause in seconds (default 3.0).
    """

    def __init__(
        self,
        enabled: bool = True,
        jitter_range: float = 0.5,
        burst_probability: float = 0.05,
        burst_min: float = 1.0,
        burst_max: float = 3.0,
    ):
        self._enabled = enabled
        self._jitter_range = max(0.0, jitter_range)
        self._burst_probability = max(0.0, min(1.0, burst_probability))
        self._burst_min = burst_min
        self._burst_max = burst_max

        # Stats
        self._total_jitter: float = 0.0
        self._total_calls: int = 0
        self._burst_count: int = 0

    # ── Public API ────────────────────────────────────────────────────────

    async def apply(self) -> float:
        """
        Wait for a random jitter duration.

        Returns the actual jitter applied (seconds).  If jitter is
        disabled, returns 0.0 immediately.
        """
        if not self._enabled:
            return 0.0

        jitter = random.uniform(0.0, self._jitter_range)

        # Occasional burst pause (human-like hesitation)
        if random.random() < self._burst_probability:
            burst = random.uniform(self._burst_min, self._burst_max)
            jitter += burst
            self._burst_count += 1
            logger.debug("Burst pause: +%.2fs (total jitter %.2fs)", burst, jitter)

        if jitter > 0:
            await asyncio.sleep(jitter)

        self._total_jitter += jitter
        self._total_calls += 1
        return jitter

    def get_stats(self) -> JitterStats:
        """Return accumulated jitter statistics."""
        avg = self._total_jitter / self._total_calls if self._total_calls else 0.0
        return JitterStats(
            total_jitter_applied_s=round(self._total_jitter, 3),
            total_calls=self._total_calls,
            avg_jitter_s=round(avg, 4),
            burst_pauses=self._burst_count,
        )

    # ── Configuration helpers ─────────────────────────────────────────────

    def set_range(self, jitter_range: float):
        """Update the jitter range at runtime."""
        self._jitter_range = max(0.0, jitter_range)

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled
