"""
Aegis AI — Request Engine
Manages all HTTP requests with rate limiting, retry logic, and response analysis.
This is the low-level HTTP layer used by all agents.
"""
import asyncio
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from urllib.parse import urljoin, urlparse

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import urllib.request
    import urllib.error

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
from utils.config import config
from utils.logger import get_logger
from backend.stealth.adaptive_scanner import AdaptiveScanner

logger = get_logger(__name__, "RECON")


@dataclass
class HttpResponse:
    """Normalized HTTP response container."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: float
    redirect_chain: List[str] = field(default_factory=list)
    error: Optional[str] = None
    body_hash: str = ""

    def __post_init__(self):
        self.body_hash = hashlib.md5(self.body.encode()).hexdigest()

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type

    @property
    def body_size(self) -> int:
        return len(self.body.encode())


class RateLimiter:
    """Token bucket rate limiter to avoid overwhelming targets."""

    def __init__(self, requests_per_second: float = 2.0):
        self.delay = 1.0 / requests_per_second
        self._last_request = 0.0

    async def acquire(self):
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        self._last_request = time.monotonic()


class RequestEngine:
    """
    Centralized HTTP request engine for all Aegis agents.

    Features:
    - Async HTTP requests with httpx
    - Rate limiting to avoid detection/overload
    - Automatic retry on transient failures
    - Response normalization
    - Session management with cookies
    """

    def __init__(self, target_url: str, authorized: bool = False):
        self.target_url = target_url
        self.authorized = authorized
        self.base_domain = urlparse(target_url).netloc
        self.rate_limiter = RateLimiter(
            requests_per_second=1.0 / config.scan.delay_between_requests
        )
        self.session_cookies: Dict[str, str] = {}
        self._auth_headers: Dict[str, str] = {}  # injected by SessionManager
        self.request_count = 0
        self._baseline_response: Optional[HttpResponse] = None

        # ── Stealth subsystem ──────────────────────────────────────────
        self.stealth = AdaptiveScanner(
            base_delay=config.scan.delay_between_requests,
            max_requests_per_second=config.scan.max_requests_per_second,
            jitter_enabled=config.scan.jitter,
            adaptive_throttle=config.scan.adaptive_throttle,
            max_concurrency=config.scan.max_concurrent_requests,
        )

    def _default_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": config.scan.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def _is_same_domain(self, url: str) -> bool:
        """Ensure we only scan the authorized target domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    async def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        """Send an async GET request."""
        return await self._request(
            "GET", url, params=params,
            headers=headers, timeout=timeout,
            allow_redirects=allow_redirects
        )

    async def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = None,
    ) -> HttpResponse:
        """Send an async POST request."""
        return await self._request(
            "POST", url, data=data, json_data=json,
            headers=headers, timeout=timeout
        )

    async def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = None,
        allow_redirects: bool = True,
        retries: int = 2,
    ) -> HttpResponse:
        """Core request method with rate limiting and retry logic."""
        if not self._is_same_domain(url):
            logger.warning(f"Blocked out-of-scope request to {url}")
            return HttpResponse(
                url=url, status_code=0, headers={}, body="",
                response_time_ms=0, error="Out of scope"
            )

        # ── Stealth: throttle + jitter before every request ────────
        await self.stealth.before_request()
        await self.rate_limiter.acquire()

        merged_headers = {**self._default_headers(), **self._auth_headers, **(headers or {})}

        # Apply rotated User-Agent if WAF evasion is active
        if self.stealth.active_user_agent:
            merged_headers["User-Agent"] = self.stealth.active_user_agent
        if self.session_cookies:
            merged_headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self.session_cookies.items()
            )

        timeout_val = timeout or config.scan.request_timeout
        start_time = time.monotonic()

        for attempt in range(retries + 1):
            try:
                if HTTPX_AVAILABLE:
                    async with httpx.AsyncClient(
                        follow_redirects=allow_redirects,
                        timeout=timeout_val,
                        verify=False,  # Security testing context
                    ) as client:
                        resp = await client.request(
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=merged_headers,
                        )
                        elapsed = (time.monotonic() - start_time) * 1000
                        self.request_count += 1

                        # Capture session cookies
                        for k, v in resp.cookies.items():
                            self.session_cookies[k] = v

                        response = HttpResponse(
                            url=str(resp.url),
                            status_code=resp.status_code,
                            headers=dict(resp.headers),
                            body=resp.text[:50000],  # Cap at 50KB
                            response_time_ms=elapsed,
                            redirect_chain=[str(r.url) for r in resp.history],
                        )

                        # ── Stealth: monitor response for WAF signals ──
                        self.stealth.after_response(
                            resp.status_code,
                            dict(resp.headers),
                            resp.text[:10000],
                        )

                        return response
                else:
                    # Fallback to stdlib urllib for sync operation
                    return await self._urllib_request(
                        method, url, merged_headers, params, data, timeout_val
                    )

            except Exception as e:
                elapsed = (time.monotonic() - start_time) * 1000
                if attempt == retries:
                    logger.debug(f"Request failed after {retries+1} attempts: {url} — {e}")
                    return HttpResponse(
                        url=url, status_code=0, headers={},
                        body="", response_time_ms=elapsed, error=str(e)
                    )
                await asyncio.sleep(0.5 * (attempt + 1))

    async def _urllib_request(
        self, method, url, headers, params=None, data=None, timeout=10
    ) -> HttpResponse:
        """Fallback sync urllib implementation wrapped in executor."""
        import urllib.request as ur
        import urllib.error
        import urllib.parse
        import json as json_mod

        def _sync_request():
            start = time.monotonic()
            try:
                if params:
                    url_with_params = url + "?" + urllib.parse.urlencode(params)
                else:
                    url_with_params = url

                req = ur.Request(url_with_params, headers=headers, method=method)
                if data:
                    req.data = urllib.parse.urlencode(data).encode()

                with ur.urlopen(req, timeout=timeout) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    body = resp.read().decode("utf-8", errors="replace")[:50000]
                    resp_headers = dict(resp.headers)
                    return HttpResponse(
                        url=url_with_params,
                        status_code=resp.status,
                        headers=resp_headers,
                        body=body,
                        response_time_ms=elapsed,
                    )
            except urllib.error.HTTPError as e:
                elapsed = (time.monotonic() - start) * 1000
                return HttpResponse(
                    url=url, status_code=e.code, headers={},
                    body="", response_time_ms=elapsed, error=str(e)
                )
            except Exception as e:
                elapsed = (time.monotonic() - start) * 1000
                return HttpResponse(
                    url=url, status_code=0, headers={},
                    body="", response_time_ms=elapsed, error=str(e)
                )

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_request)

    async def get_baseline(self, url: str) -> Optional[HttpResponse]:
        """
        Get a baseline response for comparison during exploit testing.
        Used by anomaly detection to identify normal behavior.
        """
        if not self._baseline_response:
            self._baseline_response = await self.get(url)
        return self._baseline_response

    def compare_responses(
        self, baseline: HttpResponse, test: HttpResponse
    ) -> Dict[str, Any]:
        """
        Compare two responses to detect anomalies caused by payloads.
        Returns a dict of differences and their significance.
        """
        comparison = {
            "status_code_changed": baseline.status_code != test.status_code,
            "status_code_delta": test.status_code - baseline.status_code,
            "body_size_delta": test.body_size - baseline.body_size,
            "body_changed": baseline.body_hash != test.body_hash,
            "time_delta_ms": test.response_time_ms - baseline.response_time_ms,
            "time_ratio": (
                test.response_time_ms / baseline.response_time_ms
                if baseline.response_time_ms > 0 else 1.0
            ),
            "redirect_changed": len(baseline.redirect_chain) != len(test.redirect_chain),
            "content_type_changed": baseline.content_type != test.content_type,
        }

        # Compute overall anomaly score (0.0 = normal, 1.0 = highly anomalous)
        score = 0.0
        if comparison["status_code_changed"]:
            score += 0.3
        if abs(comparison["body_size_delta"]) > 100:
            score += min(0.2, abs(comparison["body_size_delta"]) / 10000)
        if comparison["time_ratio"] > 3.0:
            score += 0.3
        if comparison["redirect_changed"]:
            score += 0.2

        comparison["anomaly_score"] = min(1.0, score)
        return comparison
