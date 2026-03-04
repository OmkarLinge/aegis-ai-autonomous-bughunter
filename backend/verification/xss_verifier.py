"""
Aegis AI — Multi-Stage XSS Verifier

  Stage 1 — Reflection Test
      Check if payload is reflected back in the response body unencoded.

  Stage 2 — Context Analysis
      Determine if reflected payload lands inside an exploitable context
      (HTML body, attribute, script block, event handler).

  Stage 3 — CSP & Sanitisation Check
      Check Content-Security-Policy, X-XSS-Protection, and encoding.
      If CSP blocks inline scripts, downgrade confidence.
"""
from __future__ import annotations

import re
import html as html_mod
from dataclasses import dataclass
from typing import Dict, List, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from scanner.request_engine import RequestEngine, HttpResponse
from backend.analysis.response_fingerprint import ResponseFingerprint
from utils.logger import get_logger

logger = get_logger(__name__, "VERIFY-XSS")


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

# Regex patterns that indicate the payload landed in a dangerous context
CONTEXT_PATTERNS = [
    (r"<script[^>]*>[^<]*alert\s*\(", "script-block"),
    (r"onerror\s*=\s*['\"]?alert", "event-handler"),
    (r"onload\s*=\s*['\"]?alert", "event-handler"),
    (r"onmouseover\s*=\s*['\"]?alert", "event-handler"),
    (r"onfocus\s*=\s*['\"]?alert", "event-handler"),
    (r"<svg[^>]*onload", "svg-handler"),
    (r"<img[^>]*onerror", "img-handler"),
    (r"javascript\s*:", "javascript-uri"),
]


@dataclass
class XSSVerificationResult:
    verified: bool = False
    stage_reached: int = 0
    confidence: float = 0.0
    technique: str = ""        # reflected | dom-based | stored
    context: str = ""          # script-block | event-handler | attribute | body
    csp_blocks: bool = False
    evidence: str = ""
    request_evidence: str = ""
    response_evidence: str = ""


class XSSVerifier:
    """Three-stage XSS verifier."""

    async def verify(
        self,
        url: str,
        parameter: str,
        engine: RequestEngine,
    ) -> XSSVerificationResult:
        from urllib.parse import urlparse, parse_qs, urlencode

        result = XSSVerificationResult()

        baseline_resp = await engine.get_baseline(url)
        if baseline_resp.error:
            return result

        for payload in XSS_PAYLOADS:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[parameter] = [payload]
            test_url = parsed._replace(
                query=urlencode({k: v[0] for k, v in qs.items()})
            ).geturl()

            resp = await engine.get(test_url)
            if resp.error:
                continue

            req_str = f"GET {test_url} HTTP/1.1"
            resp_str = self._format_response(resp)

            # ── Stage 1: Reflection ──────────────────────────────────────
            reflected_raw = payload in resp.body
            reflected_encoded = html_mod.escape(payload) in resp.body

            if not reflected_raw and not reflected_encoded:
                continue

            result.stage_reached = 1
            result.request_evidence = req_str
            result.response_evidence = resp_str

            if reflected_encoded and not reflected_raw:
                result.evidence = "Payload reflected HTML-encoded — low exploitability"
                result.confidence = 0.25
                result.technique = "reflected"
                continue

            # ── Stage 2: Context Analysis ────────────────────────────────
            context = self._detect_context(resp.body, payload)
            result.stage_reached = 2
            result.context = context

            if context in ("script-block", "event-handler", "svg-handler",
                           "img-handler", "javascript-uri"):
                result.verified = True
                result.confidence = 0.90
                result.technique = "reflected"
                result.evidence = (
                    f"Payload reflected in exploitable context: {context}\n"
                    f"Payload: {payload}"
                )
            else:
                result.evidence = (
                    f"Payload reflected in body but context is '{context}'\n"
                    f"Payload: {payload}"
                )
                result.confidence = 0.55

            # ── Stage 3: CSP Check ───────────────────────────────────────
            csp = resp.headers.get("content-security-policy", "")
            xss_protection = resp.headers.get("x-xss-protection", "")

            if csp and ("script-src" in csp or "default-src" in csp):
                if "'unsafe-inline'" not in csp:
                    result.csp_blocks = True
                    result.confidence = max(result.confidence - 0.30, 0.15)
                    result.evidence += "\nCSP blocks inline scripts — exploitation unlikely"
                    result.verified = False

            if xss_protection.startswith("1") and "mode=block" in xss_protection:
                result.confidence = max(result.confidence - 0.10, 0.10)
                result.evidence += "\nX-XSS-Protection header is enabled"

            result.stage_reached = 3

            if result.verified:
                return result

        return result

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _detect_context(body: str, payload: str) -> str:
        for pattern, ctx in CONTEXT_PATTERNS:
            if re.search(pattern, body, re.I):
                return ctx
        # Fallback: the payload is somewhere in the body text
        if payload in body:
            return "body"
        return "unknown"

    @staticmethod
    def _format_response(resp: HttpResponse, max_body: int = 300) -> str:
        lines = [f"HTTP/1.1 {resp.status_code}"]
        for k, v in list(resp.headers.items())[:10]:
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(resp.body[:max_body])
        return "\n".join(lines)
