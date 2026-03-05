"""
Aegis AI — Adaptive Scanner Controller

Central intelligence layer that coordinates all stealth subsystems:

    • AdaptiveThrottler  — dynamic inter-request delay
    • RequestJitter      — random timing noise
    • WAFEvasionEngine   — blocking detection & evasion actions

The controller exposes a simple three-method API consumed by
``RequestEngine``:

    before_request()   — throttle + jitter before every outbound request
    after_response()   — analyse response, adapt strategy, emit signals
    get_diagnostics()  — return full stealth telemetry for the dashboard

It also accepts external signals (e.g. from the ReasoningAgent's WAF
detection) to pre-configure evasion parameters.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from backend.stealth.throttler import (
    AdaptiveThrottler, THREAT_NONE, THREAT_SUSPICIOUS, THREAT_BLOCKED,
)
from backend.stealth.request_jitter import RequestJitter
from backend.stealth.waf_evasion import (
    WAFEvasionEngine, WAFSignal, EvasionAction, EncodingStrategy,
)
from utils.logger import get_logger

logger = get_logger(__name__, "ADAPTIVE")


@dataclass
class StealthDiagnostics:
    """Full stealth subsystem telemetry snapshot."""
    # Throttler
    current_delay: float = 0.0
    base_delay: float = 0.0
    threat_level: int = 0
    threat_level_name: str = "NONE"
    total_requests: int = 0

    # Jitter
    jitter_enabled: bool = True
    total_jitter_s: float = 0.0
    burst_pauses: int = 0

    # WAF evasion
    waf_signals_detected: int = 0
    last_waf_signal: str = "none"
    current_encoding: str = "plain"
    current_concurrency: int = 5
    evasion_actions_taken: int = 0
    waf_evasion_active: bool = False

    # Controller
    total_before_calls: int = 0
    total_after_calls: int = 0
    avg_total_wait_s: float = 0.0
    external_signals_received: int = 0


@dataclass
class MonitorResult:
    """Result of ``after_response()`` — tells the caller what changed."""
    evasion_triggered: bool = False
    new_delay: float = 0.0
    new_concurrency: int = 5
    new_encoding: str = "plain"
    new_user_agent: Optional[str] = None
    reason: str = ""


class AdaptiveScanner:
    """
    Central stealth controller that wraps every HTTP request
    in the engine with adaptive rate-limiting, jitter, and
    WAF evasion logic.

    Parameters
    ----------
    base_delay : float
        Base inter-request delay (default 0.5s).
    max_requests_per_second : float
        Hard upper bound on request rate (default 3.0).
    jitter_enabled : bool
        Enable random timing jitter (default True).
    adaptive_throttle : bool
        Enable adaptive throttle escalation (default True).
    max_concurrency : int
        Starting concurrency level (default 5).
    on_event : callable, optional
        Async callback for dashboard events.
    """

    def __init__(
        self,
        base_delay: float = 0.5,
        max_requests_per_second: float = 3.0,
        jitter_enabled: bool = True,
        adaptive_throttle: bool = True,
        max_concurrency: int = 5,
        on_event: Optional[Callable] = None,
    ):
        self._adaptive_enabled = adaptive_throttle
        self._max_concurrency = max_concurrency
        self._current_concurrency = max_concurrency
        self._on_event = on_event

        # Sub-components
        self._throttler = AdaptiveThrottler(
            base_delay=base_delay,
            max_requests_per_second=max_requests_per_second,
        )
        self._jitter = RequestJitter(enabled=jitter_enabled)
        self._waf_engine = WAFEvasionEngine(max_concurrency=max_concurrency)

        # Telemetry
        self._before_calls = 0
        self._after_calls = 0
        self._total_wait_s: float = 0.0
        self._external_signals = 0

        # Current User-Agent (None = use default from config)
        self._active_user_agent: Optional[str] = None

    # ── Core API (called by RequestEngine) ────────────────────────────────

    async def before_request(self) -> float:
        """
        Called **before** every HTTP request.
        Applies throttle delay + jitter.

        Returns total wait time in seconds.
        """
        self._before_calls += 1

        # 1. Throttle
        throttle_wait = await self._throttler.wait()

        # 2. Jitter
        jitter_wait = await self._jitter.apply()

        total = throttle_wait + jitter_wait
        self._total_wait_s += total
        return total

    def after_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> MonitorResult:
        """
        Called **after** every HTTP response.
        Feeds the throttler and WAF engine, returns adaptation instructions.
        """
        self._after_calls += 1
        result = MonitorResult(
            new_concurrency=self._current_concurrency,
            new_encoding=self._waf_engine.get_current_encoding().value,
        )

        # 1. Feed throttler
        if self._adaptive_enabled:
            self._throttler.record_response(status_code)
            result.new_delay = self._throttler.current_delay

        # 2. WAF evasion analysis
        action = self._waf_engine.analyze_response(status_code, headers, body)
        if action is not None:
            result.evasion_triggered = True
            result.reason = action.reason
            result.new_encoding = action.new_encoding.value

            if action.reduce_concurrency:
                self._current_concurrency = action.recommended_concurrency
                result.new_concurrency = self._current_concurrency

            if action.rotate_user_agent and action.new_user_agent:
                self._active_user_agent = action.new_user_agent
                result.new_user_agent = action.new_user_agent

            logger.warning("Evasion action: %s", action.reason)

        return result

    def monitor(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> MonitorResult:
        """
        Alias for ``after_response()`` — matches the spec's
        ``adaptive_scanner.monitor()`` call signature.
        """
        return self.after_response(status_code, headers, body)

    # ── External signal intake ────────────────────────────────────────────

    def receive_waf_signal(self, waf_type: str, evasion_level: int):
        """
        Accept a WAF detection signal from an external source
        (e.g. ReasoningAgent).

        This pre-configures the evasion engine so it is ready
        *before* the first block actually occurs.
        """
        self._external_signals += 1
        logger.info(
            "External WAF signal: type=%s, evasion_level=%d", waf_type, evasion_level,
        )

        # Pre-emptively reduce concurrency and raise encoding
        if evasion_level >= 2:
            self._current_concurrency = max(1, self._max_concurrency // 3)
            self._waf_engine._encoding_index = 2  # start at MIXED_CASE
            self._jitter.set_range(1.0)  # wider jitter
        elif evasion_level >= 1:
            self._current_concurrency = max(2, self._max_concurrency // 2)
            self._waf_engine._encoding_index = 1  # URL_ENCODE
            self._jitter.set_range(0.75)

    # ── Diagnostics ───────────────────────────────────────────────────────

    def get_diagnostics(self) -> StealthDiagnostics:
        """Return a full snapshot of all stealth subsystem states."""
        ts = self._throttler.get_state()
        js = self._jitter.get_stats()
        ws = self._waf_engine.get_state()

        _LEVEL_NAMES = {THREAT_NONE: "NONE", THREAT_SUSPICIOUS: "SUSPICIOUS", THREAT_BLOCKED: "BLOCKED"}

        avg_wait = self._total_wait_s / self._before_calls if self._before_calls else 0.0

        return StealthDiagnostics(
            current_delay=ts.current_delay,
            base_delay=ts.base_delay,
            threat_level=ts.threat_level,
            threat_level_name=_LEVEL_NAMES.get(ts.threat_level, "UNKNOWN"),
            total_requests=ts.total_requests,
            jitter_enabled=self._jitter.enabled,
            total_jitter_s=js.total_jitter_applied_s,
            burst_pauses=js.burst_pauses,
            waf_signals_detected=ws.signals_detected,
            last_waf_signal=ws.last_signal,
            current_encoding=ws.current_encoding,
            current_concurrency=self._current_concurrency,
            evasion_actions_taken=ws.total_evasion_actions,
            waf_evasion_active=ws.active,
            total_before_calls=self._before_calls,
            total_after_calls=self._after_calls,
            avg_total_wait_s=round(avg_wait, 4),
            external_signals_received=self._external_signals,
        )

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def current_concurrency(self) -> int:
        return self._current_concurrency

    @property
    def active_user_agent(self) -> Optional[str]:
        return self._active_user_agent

    @property
    def throttler(self) -> AdaptiveThrottler:
        return self._throttler

    @property
    def jitter(self) -> RequestJitter:
        return self._jitter

    @property
    def waf_engine(self) -> WAFEvasionEngine:
        return self._waf_engine
