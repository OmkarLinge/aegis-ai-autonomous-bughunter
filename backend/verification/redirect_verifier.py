"""
Aegis AI — Multi-Stage Open Redirect Verifier

  Stage 1 — Parameter Injection with external URL.
  Stage 2 — Confirm 3xx status + Location header → external domain.
  Stage 3 — Protocol-relative and obfuscated payloads.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from scanner.request_engine import RequestEngine, HttpResponse
from utils.logger import get_logger

logger = get_logger(__name__, "VERIFY-REDIRECT")

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/%2f%2e%2e",
    "https://evil。com",                # unicode dot
    "/\\evil.com",
    "https://evil.com?@legit.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirectUrl", "next", "url",
    "return", "returnTo", "returnUrl", "goto", "destination",
    "target", "to", "link", "ref", "continue",
]


@dataclass
class RedirectVerificationResult:
    verified: bool = False
    stage_reached: int = 0
    confidence: float = 0.0
    redirect_url: str = ""
    external_domain: str = ""
    evidence: str = ""
    request_evidence: str = ""
    response_evidence: str = ""


class OpenRedirectVerifier:
    """Three-stage Open Redirect verifier."""

    async def verify(
        self,
        url: str,
        engine: RequestEngine,
    ) -> RedirectVerificationResult:
        result = RedirectVerificationResult()
        target_domain = urlparse(url).netloc

        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = parsed._replace(
                    query=urlencode({k: v[0] for k, v in qs.items()})
                ).geturl()

                resp = await engine.get(test_url, allow_redirects=False)
                if resp.error:
                    continue

                req_str = f"GET {test_url} HTTP/1.1"
                resp_str = self._format_response(resp)

                # Stage 1: must be a redirect status
                if resp.status_code not in (301, 302, 303, 307, 308):
                    continue
                result.stage_reached = 1

                # Stage 2: Location header → external domain
                location = resp.headers.get("location", "")
                if not location:
                    continue

                loc_domain = urlparse(location).netloc
                result.stage_reached = 2

                if loc_domain and loc_domain != target_domain:
                    result.verified = True
                    result.confidence = 0.95
                    result.redirect_url = location
                    result.external_domain = loc_domain
                    result.stage_reached = 3
                    result.evidence = (
                        f"Confirmed open redirect:\n"
                        f"  {resp.status_code} → {location}\n"
                        f"  Target domain: {target_domain}\n"
                        f"  Redirect domain: {loc_domain}\n"
                        f"  Parameter: {param}\n"
                        f"  Payload: {payload}"
                    )
                    result.request_evidence = req_str
                    result.response_evidence = resp_str
                    return result

                # Same domain but payload echoed
                if payload in location:
                    result.confidence = max(result.confidence, 0.35)
                    result.evidence = f"Payload in Location but same-domain: {location}"
                    result.request_evidence = req_str
                    result.response_evidence = resp_str

        return result

    @staticmethod
    def _format_response(resp: HttpResponse, max_body: int = 200) -> str:
        lines = [f"HTTP/1.1 {resp.status_code}"]
        for k, v in list(resp.headers.items())[:10]:
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(resp.body[:max_body])
        return "\n".join(lines)
