"""
Aegis AI — WAF Evasion Engine

Detects when a Web Application Firewall is actively blocking or
challenging the scanner and takes corrective action:

Detection signals:
    • HTTP 403 Forbidden
    • HTTP 429 Too Many Requests
    • CAPTCHA / JavaScript challenge pages
    • Cloudflare "Attention Required" interstitials
    • Generic "Access Denied" body text

Evasion responses:
    1. Signal the throttler to slow down
    2. Rotate payload encoding (URL-encode, double-encode, Unicode)
    3. Reduce scanner concurrency
    4. Optionally rotate User-Agent strings
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))
from utils.logger import get_logger

logger = get_logger(__name__, "WAF_EVASION")


# ── WAF blocking patterns ────────────────────────────────────────────────────

class WAFSignal(Enum):
    """Type of WAF blocking signal detected."""
    NONE         = "none"
    RATE_LIMITED  = "rate_limited"         # 429
    FORBIDDEN     = "forbidden"            # 403
    CAPTCHA       = "captcha"              # CAPTCHA page
    JS_CHALLENGE  = "js_challenge"         # Cloudflare JS challenge
    ACCESS_DENIED = "access_denied"        # Generic block page
    CONNECTION_DROP = "connection_drop"    # 444/520-525


_CAPTCHA_PATTERNS: List[re.Pattern] = [
    re.compile(r"captcha", re.I),
    re.compile(r"recaptcha", re.I),
    re.compile(r"hcaptcha", re.I),
    re.compile(r"g-recaptcha", re.I),
    re.compile(r"cf-turnstile", re.I),
]

_CHALLENGE_PATTERNS: List[re.Pattern] = [
    re.compile(r"attention\s+required", re.I),
    re.compile(r"checking\s+your\s+browser", re.I),
    re.compile(r"please\s+wait.*redirected", re.I),
    re.compile(r"just\s+a\s+moment", re.I),
    re.compile(r"cf[-_]?challenge", re.I),
    re.compile(r"jschl[-_]?vc", re.I),          # Cloudflare JS challenge param
]

_ACCESS_DENIED_PATTERNS: List[re.Pattern] = [
    re.compile(r"access\s+denied", re.I),
    re.compile(r"request\s+blocked", re.I),
    re.compile(r"forbidden", re.I),
    re.compile(r"not\s+allowed", re.I),
    re.compile(r"web\s+application\s+firewall", re.I),
    re.compile(r"security\s+check", re.I),
]

# Status code families
_RATE_LIMIT_CODES   = frozenset({429})
_FORBIDDEN_CODES    = frozenset({403, 406})
_CONNECTION_CODES   = frozenset({444, 495, 496, 499, 520, 521, 522, 523, 524, 525})


# ── Payload encoding strategies ──────────────────────────────────────────────

class EncodingStrategy(Enum):
    """Payload encoding rotation strategies."""
    PLAIN        = "plain"
    URL_ENCODE   = "url_encode"
    DOUBLE_URL   = "double_url_encode"
    UNICODE      = "unicode"
    HTML_ENTITY  = "html_entity"
    MIXED_CASE   = "mixed_case"

_ENCODING_ROTATION_ORDER: List[EncodingStrategy] = [
    EncodingStrategy.PLAIN,
    EncodingStrategy.URL_ENCODE,
    EncodingStrategy.MIXED_CASE,
    EncodingStrategy.DOUBLE_URL,
    EncodingStrategy.UNICODE,
    EncodingStrategy.HTML_ENTITY,
]


# ── User-Agent pool for rotation ─────────────────────────────────────────────

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


@dataclass
class WAFEvasionState:
    """Snapshot of the evasion engine's internal state."""
    signals_detected: int
    last_signal: str
    current_encoding: str
    encoding_rotation_index: int
    ua_rotation_index: int
    recommended_concurrency: int
    total_evasion_actions: int
    active: bool


@dataclass
class EvasionAction:
    """An evasion action recommended to the adaptive scanner."""
    slow_down: bool = False
    recommended_delay: float = 0.0
    rotate_encoding: bool = False
    new_encoding: EncodingStrategy = EncodingStrategy.PLAIN
    reduce_concurrency: bool = False
    recommended_concurrency: int = 5
    rotate_user_agent: bool = False
    new_user_agent: str = ""
    reason: str = ""


class WAFEvasionEngine:
    """
    Detects WAF blocking patterns in HTTP responses and produces
    evasion actions that the adaptive scanner should apply.

    Parameters
    ----------
    max_concurrency : int
        Starting (and maximum) concurrency level (default 5).
    min_concurrency : int
        Minimum concurrency to reduce to (default 1).
    enable_ua_rotation : bool
        Whether to rotate User-Agent strings on detection (default True).
    """

    def __init__(
        self,
        max_concurrency: int = 5,
        min_concurrency: int = 1,
        enable_ua_rotation: bool = True,
    ):
        self._max_concurrency = max_concurrency
        self._min_concurrency = min_concurrency
        self._enable_ua_rotation = enable_ua_rotation

        self._encoding_index = 0
        self._ua_index = 0
        self._current_concurrency = max_concurrency
        self._signals_detected = 0
        self._total_evasion_actions = 0
        self._last_signal = WAFSignal.NONE
        self._last_detection_ts: float = 0.0
        self._active = False

    # ── Public API ────────────────────────────────────────────────────────

    def analyze_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> Optional[EvasionAction]:
        """
        Analyze an HTTP response for WAF blocking signals.

        Returns an ``EvasionAction`` if evasion is needed, or ``None``
        if the response looks normal.
        """
        signal = self._detect_signal(status_code, headers, body)

        if signal == WAFSignal.NONE:
            return None

        self._signals_detected += 1
        self._last_signal = signal
        self._last_detection_ts = time.monotonic()
        self._active = True

        action = self._build_action(signal)
        self._total_evasion_actions += 1
        logger.warning(
            "WAF signal %s detected — action: %s", signal.value, action.reason,
        )
        return action

    def get_current_encoding(self) -> EncodingStrategy:
        """Return the currently recommended encoding strategy."""
        return _ENCODING_ROTATION_ORDER[self._encoding_index % len(_ENCODING_ROTATION_ORDER)]

    def get_current_user_agent(self) -> str:
        """Return the current User-Agent from the rotation pool."""
        return _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]

    def encode_payload(self, payload: str) -> str:
        """
        Encode a payload according to the current encoding strategy.
        """
        strategy = self.get_current_encoding()

        if strategy == EncodingStrategy.PLAIN:
            return payload
        elif strategy == EncodingStrategy.URL_ENCODE:
            return self._url_encode(payload)
        elif strategy == EncodingStrategy.DOUBLE_URL:
            return self._url_encode(self._url_encode(payload))
        elif strategy == EncodingStrategy.UNICODE:
            return self._unicode_encode(payload)
        elif strategy == EncodingStrategy.HTML_ENTITY:
            return self._html_entity_encode(payload)
        elif strategy == EncodingStrategy.MIXED_CASE:
            return self._mixed_case(payload)
        return payload

    def get_state(self) -> WAFEvasionState:
        """Return a snapshot of the engine's state."""
        return WAFEvasionState(
            signals_detected=self._signals_detected,
            last_signal=self._last_signal.value,
            current_encoding=self.get_current_encoding().value,
            encoding_rotation_index=self._encoding_index,
            ua_rotation_index=self._ua_index,
            recommended_concurrency=self._current_concurrency,
            total_evasion_actions=self._total_evasion_actions,
            active=self._active,
        )

    def reset(self):
        """Reset engine to initial state."""
        self._encoding_index = 0
        self._ua_index = 0
        self._current_concurrency = self._max_concurrency
        self._signals_detected = 0
        self._total_evasion_actions = 0
        self._last_signal = WAFSignal.NONE
        self._active = False

    # ── Signal detection ──────────────────────────────────────────────────

    def _detect_signal(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> WAFSignal:
        """Identify the type of WAF blocking signal."""
        # ── Status code checks ────────────────────────────────────────
        if status_code in _RATE_LIMIT_CODES:
            return WAFSignal.RATE_LIMITED

        if status_code in _CONNECTION_CODES:
            return WAFSignal.CONNECTION_DROP

        if status_code in _FORBIDDEN_CODES:
            # Could be a legitimate 403 — check body for WAF indicators
            if self._body_matches_waf(body):
                return WAFSignal.FORBIDDEN

        # ── Body pattern checks (only on small-ish bodies) ────────────
        body_sample = body[:10_000] if body else ""

        for pattern in _CAPTCHA_PATTERNS:
            if pattern.search(body_sample):
                return WAFSignal.CAPTCHA

        for pattern in _CHALLENGE_PATTERNS:
            if pattern.search(body_sample):
                return WAFSignal.JS_CHALLENGE

        # Only flag ACCESS_DENIED when the status is also an error
        if status_code >= 400:
            for pattern in _ACCESS_DENIED_PATTERNS:
                if pattern.search(body_sample):
                    return WAFSignal.ACCESS_DENIED

        return WAFSignal.NONE

    def _body_matches_waf(self, body: str) -> bool:
        """Check if a 403 body looks like a WAF block page."""
        if not body:
            return False
        sample = body[:5_000].lower()
        waf_indicators = [
            "firewall", "blocked", "security", "cloudflare",
            "incapsula", "sucuri", "akamai", "mod_security",
            "access denied", "request blocked",
        ]
        return sum(1 for ind in waf_indicators if ind in sample) >= 2

    # ── Action building ───────────────────────────────────────────────────

    def _build_action(self, signal: WAFSignal) -> EvasionAction:
        """Build an evasion action based on the detected signal."""
        action = EvasionAction()

        if signal == WAFSignal.RATE_LIMITED:
            action.slow_down = True
            action.recommended_delay = 3.0
            action.reduce_concurrency = True
            action.recommended_concurrency = max(
                self._min_concurrency,
                self._current_concurrency // 2,
            )
            action.reason = "Rate limited (429) — halving concurrency, adding 3s delay"

        elif signal == WAFSignal.FORBIDDEN:
            action.slow_down = True
            action.recommended_delay = 5.0
            action.rotate_encoding = True
            self._encoding_index += 1
            action.new_encoding = self.get_current_encoding()
            action.reduce_concurrency = True
            action.recommended_concurrency = max(
                self._min_concurrency,
                self._current_concurrency - 1,
            )
            if self._enable_ua_rotation:
                action.rotate_user_agent = True
                self._ua_index += 1
                action.new_user_agent = self.get_current_user_agent()
            action.reason = (
                f"WAF block (403) — encoding→{action.new_encoding.value}, "
                f"concurrency→{action.recommended_concurrency}, +5s delay"
            )

        elif signal == WAFSignal.CAPTCHA:
            action.slow_down = True
            action.recommended_delay = 10.0
            action.reduce_concurrency = True
            action.recommended_concurrency = self._min_concurrency
            action.rotate_encoding = True
            self._encoding_index += 1
            action.new_encoding = self.get_current_encoding()
            if self._enable_ua_rotation:
                action.rotate_user_agent = True
                self._ua_index += 1
                action.new_user_agent = self.get_current_user_agent()
            action.reason = (
                "CAPTCHA detected — dropping to min concurrency, +10s delay, rotating encoding+UA"
            )

        elif signal == WAFSignal.JS_CHALLENGE:
            action.slow_down = True
            action.recommended_delay = 8.0
            action.reduce_concurrency = True
            action.recommended_concurrency = max(
                self._min_concurrency,
                self._current_concurrency // 2,
            )
            if self._enable_ua_rotation:
                action.rotate_user_agent = True
                self._ua_index += 1
                action.new_user_agent = self.get_current_user_agent()
            action.reason = "JS challenge — halving concurrency, +8s delay, rotating UA"

        elif signal == WAFSignal.ACCESS_DENIED:
            action.slow_down = True
            action.recommended_delay = 4.0
            action.rotate_encoding = True
            self._encoding_index += 1
            action.new_encoding = self.get_current_encoding()
            action.reason = f"Access denied — encoding→{action.new_encoding.value}, +4s delay"

        elif signal == WAFSignal.CONNECTION_DROP:
            action.slow_down = True
            action.recommended_delay = 12.0
            action.reduce_concurrency = True
            action.recommended_concurrency = self._min_concurrency
            action.reason = "Connection dropped — min concurrency, +12s delay"

        # Update internal concurrency tracker
        if action.reduce_concurrency:
            self._current_concurrency = action.recommended_concurrency

        return action

    # ── Payload encoding helpers ──────────────────────────────────────────

    @staticmethod
    def _url_encode(payload: str) -> str:
        """Percent-encode special characters."""
        import urllib.parse
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        """Replace key chars with Unicode fullwidth equivalents."""
        _MAP = {
            "<": "\uff1c", ">": "\uff1e", "'": "\uff07", '"': "\uff02",
            "(": "\uff08", ")": "\uff09", "/": "\uff0f", "\\": "\uff3c",
        }
        return "".join(_MAP.get(c, c) for c in payload)

    @staticmethod
    def _html_entity_encode(payload: str) -> str:
        """Replace key chars with HTML numeric entities."""
        _MAP = {
            "<": "&#60;", ">": "&#62;", "'": "&#39;", '"': "&#34;",
            "(": "&#40;", ")": "&#41;", "/": "&#47;",
        }
        return "".join(_MAP.get(c, c) for c in payload)

    @staticmethod
    def _mixed_case(payload: str) -> str:
        """Randomly alternate upper/lower case for tag names."""
        import random
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return "".join(result)
