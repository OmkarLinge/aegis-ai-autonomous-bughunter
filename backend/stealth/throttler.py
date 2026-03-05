"""
Aegis AI — Adaptive Request Throttler

Implements dynamic request rate control that adjusts in real-time
based on WAF response signals.  When the target appears to be
blocking or rate-limiting, the throttler automatically slows down
to keep the scan alive.

Behaviour:
    Normal scan   → base_delay (default 0.5 s)
    Suspicious    → escalated delay   (2–5 s)
    Heavy block   → backoff delay     (5–15 s)

The throttler tracks a rolling window of recent response codes
and adjusts delay continuously so the scan can resume
at normal speed once the threat passes.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))
from utils.logger import get_logger

logger = get_logger(__name__, "THROTTLER")

# ── Threat level constants ────────────────────────────────────────────────────

THREAT_NONE      = 0
THREAT_SUSPICIOUS = 1
THREAT_BLOCKED    = 2

# Status codes that indicate WAF/rate-limit pressure
_SUSPICIOUS_CODES = frozenset({429, 503})
_BLOCKED_CODES    = frozenset({403, 406, 418, 444, 495, 496, 499, 520, 521, 522, 523, 524, 525})


@dataclass
class ThrottleState:
    """Snapshot of the throttler's internal state."""
    current_delay: float
    base_delay: float
    threat_level: int
    suspicious_count: int
    blocked_count: int
    total_requests: int
    window_size: int
    max_rps: float


class AdaptiveThrottler:
    """
    Adaptive request throttler that reacts to WAF blocking signals.

    Parameters
    ----------
    base_delay : float
        Minimum inter-request delay in seconds (default 0.5).
    max_requests_per_second : float
        Hard ceiling on request rate (default 3.0).
    window_size : int
        Rolling window of recent status codes to evaluate (default 20).
    suspicious_delay : float
        Delay applied when suspicious responses are observed (default 2.0).
    blocked_delay : float
        Delay applied when outright blocking is detected (default 5.0).
    max_backoff : float
        Maximum delay cap in seconds (default 15.0).
    cooldown_requests : int
        How many clean requests before reducing threat level (default 10).
    """

    def __init__(
        self,
        base_delay: float = 0.5,
        max_requests_per_second: float = 3.0,
        window_size: int = 20,
        suspicious_delay: float = 2.0,
        blocked_delay: float = 5.0,
        max_backoff: float = 15.0,
        cooldown_requests: int = 10,
    ):
        self._base_delay = base_delay
        self._max_rps = max_requests_per_second
        self._min_delay = 1.0 / max_requests_per_second
        self._window_size = window_size
        self._suspicious_delay = suspicious_delay
        self._blocked_delay = blocked_delay
        self._max_backoff = max_backoff
        self._cooldown_requests = cooldown_requests

        # Current effective delay
        self._current_delay = max(base_delay, self._min_delay)
        self._threat_level = THREAT_NONE

        # Rolling window of recent status codes
        self._recent_codes: Deque[int] = deque(maxlen=window_size)
        self._last_request_ts: float = 0.0
        self._total_requests: int = 0
        self._clean_streak: int = 0

    # ── Public API ────────────────────────────────────────────────────────

    async def wait(self) -> float:
        """
        Block until the next request is allowed.

        Returns the actual delay waited (in seconds).
        """
        now = time.monotonic()
        elapsed = now - self._last_request_ts
        wait_time = max(0.0, self._current_delay - elapsed)

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        self._last_request_ts = time.monotonic()
        self._total_requests += 1
        return wait_time

    def record_response(self, status_code: int) -> int:
        """
        Feed a response status code to the throttler so it can adapt.

        Returns the new threat level.
        """
        self._recent_codes.append(status_code)
        self._evaluate_threat()
        return self._threat_level

    def get_state(self) -> ThrottleState:
        """Return a snapshot of the throttler's state."""
        suspicious = sum(1 for c in self._recent_codes if c in _SUSPICIOUS_CODES)
        blocked    = sum(1 for c in self._recent_codes if c in _BLOCKED_CODES)
        return ThrottleState(
            current_delay=self._current_delay,
            base_delay=self._base_delay,
            threat_level=self._threat_level,
            suspicious_count=suspicious,
            blocked_count=blocked,
            total_requests=self._total_requests,
            window_size=self._window_size,
            max_rps=self._max_rps,
        )

    def reset(self):
        """Reset throttler to initial state."""
        self._current_delay = max(self._base_delay, self._min_delay)
        self._threat_level = THREAT_NONE
        self._recent_codes.clear()
        self._clean_streak = 0
        logger.info("Throttler reset to base delay %.2fs", self._base_delay)

    @property
    def current_delay(self) -> float:
        return self._current_delay

    @property
    def threat_level(self) -> int:
        return self._threat_level

    # ── Internal logic ────────────────────────────────────────────────────

    def _evaluate_threat(self):
        """Re-evaluate threat level from the rolling window."""
        if not self._recent_codes:
            return

        suspicious = sum(1 for c in self._recent_codes if c in _SUSPICIOUS_CODES)
        blocked    = sum(1 for c in self._recent_codes if c in _BLOCKED_CODES)
        window_len = len(self._recent_codes)

        # Ratios within the rolling window
        suspicious_pct = suspicious / window_len
        blocked_pct    = blocked / window_len

        prev_level = self._threat_level

        # ── Determine threat level ────────────────────────────────────
        if blocked_pct > 0.15 or blocked >= 3:
            self._threat_level = THREAT_BLOCKED
            self._current_delay = min(
                self._blocked_delay * (1 + blocked_pct),
                self._max_backoff,
            )
            self._clean_streak = 0

        elif suspicious_pct > 0.10 or suspicious >= 2:
            self._threat_level = THREAT_SUSPICIOUS
            self._current_delay = min(
                self._suspicious_delay * (1 + suspicious_pct),
                self._max_backoff,
            )
            self._clean_streak = 0

        else:
            # No pressure — track clean streak for cooldown
            last_code = self._recent_codes[-1]
            if last_code not in _SUSPICIOUS_CODES and last_code not in _BLOCKED_CODES:
                self._clean_streak += 1
            else:
                self._clean_streak = 0

            if self._clean_streak >= self._cooldown_requests:
                # Gradually return to base delay
                self._threat_level = THREAT_NONE
                self._current_delay = max(
                    self._current_delay * 0.8,  # decay factor
                    max(self._base_delay, self._min_delay),
                )
                if self._current_delay <= max(self._base_delay, self._min_delay) + 0.05:
                    self._current_delay = max(self._base_delay, self._min_delay)

        # Log transitions
        if self._threat_level != prev_level:
            level_names = {THREAT_NONE: "NONE", THREAT_SUSPICIOUS: "SUSPICIOUS", THREAT_BLOCKED: "BLOCKED"}
            logger.warning(
                "Threat level %s → %s  (delay %.2fs, suspicious=%d, blocked=%d)",
                level_names[prev_level],
                level_names[self._threat_level],
                self._current_delay,
                suspicious,
                blocked,
            )
