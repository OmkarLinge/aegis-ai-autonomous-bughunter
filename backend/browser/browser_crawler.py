"""
Aegis AI — Headless Browser Crawler (Playwright)

Modern SPA-aware crawler that executes JavaScript, intercepts network
requests, and discovers dynamic routes invisible to HTTP-only crawling.

Capabilities:
- Launches headless Chromium via Playwright
- Waits for network-idle to capture lazily-loaded content
- Intercepts XHR / Fetch API calls made by the page
- Clicks visible buttons, submits forms, scrolls to trigger lazy load
- Returns structured BrowserCrawlResult compatible with SiteGraph

Performance constraints:
- Max 3 concurrent browser tabs (semaphore)
- 10 s timeout per page navigation
- Infinite-scroll guard (max 5 scroll iterations)
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "BROWSER")

# ── Lazy Playwright import (graceful degradation) ───────────────────────────
try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("[BROWSER] Playwright not installed — browser crawl disabled")


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class InterceptedRequest:
    """An XHR / Fetch / WebSocket request intercepted by the browser."""
    url: str
    method: str
    resource_type: str          # xhr | fetch | websocket | document | script
    post_data: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "resource_type": self.resource_type,
            "post_data": self.post_data,
        }


@dataclass
class DiscoveredForm:
    """A form discovered in the rendered DOM."""
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)
    has_file_upload: bool = False
    has_password: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "has_file_upload": self.has_file_upload,
            "has_password": self.has_password,
        }


@dataclass
class BrowserCrawlResult:
    """Complete result from crawling a single URL with the headless browser."""
    url: str
    rendered_html: str = ""
    title: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    inputs: List[Dict[str, str]] = field(default_factory=list)
    buttons: List[Dict[str, str]] = field(default_factory=list)
    api_calls: List[InterceptedRequest] = field(default_factory=list)
    js_scripts: List[str] = field(default_factory=list)        # inline + external
    technologies_detected: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    console_errors: List[str] = field(default_factory=list)
    load_time_ms: float = 0.0
    dynamic_content_loaded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "link_count": len(self.links),
            "form_count": len(self.forms),
            "api_call_count": len(self.api_calls),
            "input_count": len(self.inputs),
            "button_count": len(self.buttons),
            "load_time_ms": self.load_time_ms,
            "dynamic_content_loaded": self.dynamic_content_loaded,
            "technologies": self.technologies_detected,
            "links": self.links[:50],
            "forms": [f.to_dict() for f in self.forms],
            "api_calls": [a.to_dict() for a in self.api_calls],
        }


# ── Constants ────────────────────────────────────────────────────────────────

MAX_CONCURRENT_TABS = 3
PAGE_TIMEOUT_MS = 10_000
MAX_SCROLL_ITERATIONS = 5
INTERACTION_DELAY_MS = 300

# SPA framework signatures in rendered DOM
SPA_SIGNATURES = {
    "react":   [r"__REACT_DEVTOOLS", r"data-reactroot", r"_reactRootContainer"],
    "angular": [r"ng-version", r"ng-app", r"\[ngIf\]", r"_nghost"],
    "vue":     [r"__vue__", r"data-v-[a-f0-9]", r"v-cloak"],
    "next.js": [r"__NEXT_DATA__", r"_next/static"],
    "nuxt":    [r"__NUXT__", r"_nuxt/"],
    "svelte":  [r"__svelte", r"svelte-[a-z]"],
}


class BrowserCrawler:
    """
    Playwright-powered headless browser crawler.

    Usage::

        crawler = BrowserCrawler(target_url="https://example.com")
        results = await crawler.crawl()          # list[BrowserCrawlResult]
        await crawler.close()

    Or as an async context manager::

        async with BrowserCrawler("https://example.com") as crawler:
            results = await crawler.crawl()
    """

    def __init__(
        self,
        target_url: str,
        max_pages: int = 20,
        on_event: Optional[Callable] = None,
    ):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright is not installed.  Run: pip install playwright && playwright install chromium"
            )

        self.target_url = target_url.rstrip("/")
        self.target_domain = urlparse(target_url).netloc
        self.max_pages = max_pages
        self.on_event = on_event

        self._playwright = None
        self._browser = None
        self._context: Optional[BrowserContext] = None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_TABS)
        self._visited: Set[str] = set()
        self._api_calls: List[InterceptedRequest] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def _launch(self):
        """Launch a headless browser instance."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
            ],
        )
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0"
            ),
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        logger.info("[BROWSER] Headless Chromium launched")

    async def close(self):
        """Shut down the browser."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("[BROWSER] Browser closed")

    async def __aenter__(self):
        await self._launch()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # ── Public API ────────────────────────────────────────────────────────

    async def crawl(self) -> List[BrowserCrawlResult]:
        """
        Crawl the target using headless Chromium.

        1. Navigate to the root URL
        2. Extract links, forms, API calls from the rendered DOM
        3. Follow discovered same-domain links (BFS, up to max_pages)
        4. Return all results
        """
        if not self._browser:
            await self._launch()

        results: List[BrowserCrawlResult] = []
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put(self.target_url)

        await self._emit("BROWSER_START", f"Browser crawl starting on {self.target_url}")

        while not queue.empty() and len(results) < self.max_pages:
            url = await queue.get()
            normalised = self._normalise(url)
            if normalised in self._visited:
                continue
            self._visited.add(normalised)

            try:
                result = await self._crawl_page(url)
                results.append(result)

                await self._emit(
                    "BROWSER_PAGE",
                    f"Browser rendered {url} ({len(result.links)} links, "
                    f"{len(result.api_calls)} API calls)",
                    result.to_dict(),
                )

                # Queue new same-domain links
                for link in result.links:
                    norm = self._normalise(link)
                    if norm not in self._visited and self._is_same_domain(link):
                        await queue.put(link)

            except Exception as exc:
                logger.warning("[BROWSER] Error on %s: %s", url, exc)

        await self._emit(
            "BROWSER_COMPLETE",
            f"Browser crawl complete: {len(results)} pages rendered, "
            f"{sum(len(r.api_calls) for r in results)} API calls intercepted",
        )

        return results

    async def crawl_single(self, url: str) -> BrowserCrawlResult:
        """Crawl a single page (used by the pipeline for targeted recon)."""
        if not self._browser:
            await self._launch()
        return await self._crawl_page(url)

    # ── Core page crawler ─────────────────────────────────────────────────

    async def _crawl_page(self, url: str) -> BrowserCrawlResult:
        """Navigate to a URL and extract everything from the rendered DOM."""
        start = time.monotonic()
        result = BrowserCrawlResult(url=url)

        async with self._semaphore:
            page: Page = await self._context.new_page()
            page_api_calls: List[InterceptedRequest] = []

            try:
                # ── Set up network interception ─────────────────────────
                page.on("request", lambda req: self._on_request(req, page_api_calls))
                page.on("console", lambda msg: self._on_console(msg, result))

                # ── Navigate ────────────────────────────────────────────
                await page.goto(url, wait_until="networkidle", timeout=PAGE_TIMEOUT_MS)

                # ── Extract base content ────────────────────────────────
                result.title = await page.title()
                result.rendered_html = await page.content()

                # ── Extract links ───────────────────────────────────────
                result.links = await self._extract_links(page, url)

                # ── Extract forms ───────────────────────────────────────
                result.forms = await self._extract_forms(page, url)

                # ── Extract standalone inputs ───────────────────────────
                result.inputs = await self._extract_inputs(page)

                # ── Extract buttons ─────────────────────────────────────
                result.buttons = await self._extract_buttons(page)

                # ── Extract inline/external JS URLs ─────────────────────
                result.js_scripts = await self._extract_scripts(page, url)

                # ── Simulate interactions ───────────────────────────────
                await self._interact(page, result)

                # ── Cookies ─────────────────────────────────────────────
                cookies_list = await self._context.cookies(url)
                result.cookies = {c["name"]: c["value"] for c in cookies_list}

                # ── Detect SPA frameworks ───────────────────────────────
                result.technologies_detected = self._detect_spa(result.rendered_html)

                # ── Store intercepted API calls ─────────────────────────
                result.api_calls = page_api_calls
                self._api_calls.extend(page_api_calls)

            except Exception as exc:
                logger.debug("[BROWSER] Page error %s: %s", url, exc)
            finally:
                await page.close()

        result.load_time_ms = (time.monotonic() - start) * 1000
        logger.info(
            "[BROWSER] %s | links=%d forms=%d api=%d time=%.0fms",
            url, len(result.links), len(result.forms),
            len(result.api_calls), result.load_time_ms,
        )
        return result

    # ── Extraction helpers ────────────────────────────────────────────────

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """Extract all anchor hrefs from the rendered DOM."""
        raw = await page.eval_on_selector_all(
            "a[href]",
            """els => els.map(a => a.href).filter(h => h && !h.startsWith('javascript:') && !h.startsWith('mailto:'))"""
        )
        links: List[str] = []
        seen: Set[str] = set()
        for href in raw:
            full = urljoin(base_url, href)
            norm = self._normalise(full)
            if norm not in seen and self._is_same_domain(full):
                seen.add(norm)
                links.append(full)
        return links

    async def _extract_forms(self, page: Page, base_url: str) -> List[DiscoveredForm]:
        """Extract form elements from the rendered DOM."""
        raw_forms = await page.eval_on_selector_all("form", """
            forms => forms.map(f => ({
                action: f.action || '',
                method: (f.method || 'GET').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                    name: i.name || '',
                    type: i.type || 'text',
                    id: i.id || '',
                    placeholder: i.placeholder || '',
                    required: i.required,
                })),
                hasFileUpload: !!f.querySelector('input[type=file]'),
                hasPassword:   !!f.querySelector('input[type=password]'),
            }))
        """)
        forms: List[DiscoveredForm] = []
        for f in raw_forms:
            action = urljoin(base_url, f.get("action", "")) if f.get("action") else base_url
            forms.append(DiscoveredForm(
                action=action,
                method=f.get("method", "GET"),
                inputs=[inp for inp in f.get("inputs", []) if inp.get("name")],
                has_file_upload=f.get("hasFileUpload", False),
                has_password=f.get("hasPassword", False),
            ))
        return forms

    async def _extract_inputs(self, page: Page) -> List[Dict[str, str]]:
        """Extract standalone inputs (outside forms) from the DOM."""
        return await page.eval_on_selector_all(
            "input:not(form input), textarea:not(form textarea)",
            """els => els.map(i => ({
                name: i.name || '',
                type: i.type || 'text',
                id: i.id || '',
                placeholder: i.placeholder || '',
            })).filter(i => i.name || i.id)"""
        )

    async def _extract_buttons(self, page: Page) -> List[Dict[str, str]]:
        """Extract buttons and clickable elements."""
        return await page.eval_on_selector_all(
            "button, [role=button], input[type=submit], input[type=button]",
            """els => els.slice(0, 30).map(b => ({
                text: (b.textContent || b.value || '').trim().substring(0, 100),
                type: b.type || 'button',
                id: b.id || '',
                onclick: b.getAttribute('onclick') || '',
            }))"""
        )

    async def _extract_scripts(self, page: Page, base_url: str) -> List[str]:
        """Extract external script URLs and inline script snippets."""
        external = await page.eval_on_selector_all(
            "script[src]",
            "els => els.map(s => s.src)"
        )
        inline_snippets = await page.eval_on_selector_all(
            "script:not([src])",
            "els => els.map(s => s.textContent.substring(0, 2000))"
        )
        scripts: List[str] = []
        for src in external:
            scripts.append(urljoin(base_url, src))
        # Include first 500 chars of inline scripts (for endpoint extraction)
        for snippet in inline_snippets:
            if snippet and len(snippet.strip()) > 10:
                scripts.append(f"inline:{snippet[:500]}")
        return scripts

    # ── Interaction simulation ────────────────────────────────────────────

    async def _interact(self, page: Page, result: BrowserCrawlResult):
        """
        Simulate basic user interactions to trigger dynamic content.

        1. Click visible, non-navigation buttons
        2. Scroll to trigger lazy-loaded content
        3. Record any new API calls / DOM changes
        """
        initial_links = len(result.links)

        # ── Click visible buttons (non-submit, non-navigation) ──────────
        try:
            buttons = await page.query_selector_all(
                "button:visible, [role=button]:visible"
            )
            for btn in buttons[:5]:  # max 5 to avoid loops
                try:
                    # Skip if button navigates away
                    btn_text = (await btn.text_content() or "").lower()
                    skip_words = {"logout", "delete", "remove", "cancel", "close", "sign out"}
                    if any(w in btn_text for w in skip_words):
                        continue

                    await btn.click(timeout=2000, no_wait_after=True)
                    await page.wait_for_timeout(INTERACTION_DELAY_MS)
                except Exception:
                    pass
        except Exception:
            pass

        # ── Scroll to trigger lazy load ─────────────────────────────────
        try:
            prev_height = 0
            for _ in range(MAX_SCROLL_ITERATIONS):
                current_height = await page.evaluate("document.body.scrollHeight")
                if current_height == prev_height:
                    break
                prev_height = current_height
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(500)

            # Scroll back to top
            await page.evaluate("window.scrollTo(0, 0)")
        except Exception:
            pass

        # ── Re-extract links after interactions ─────────────────────────
        try:
            new_html = await page.content()
            if len(new_html) > len(result.rendered_html) + 200:
                result.dynamic_content_loaded = True
                result.rendered_html = new_html
                # Re-extract links from updated DOM
                new_links = await self._extract_links(page, result.url)
                existing = set(result.links)
                for link in new_links:
                    if link not in existing:
                        result.links.append(link)
        except Exception:
            pass

        if len(result.links) > initial_links:
            logger.debug(
                "[BROWSER] Interactions discovered %d new links on %s",
                len(result.links) - initial_links, result.url,
            )

    # ── Network interception ──────────────────────────────────────────────

    def _on_request(self, request, api_calls: List[InterceptedRequest]):
        """Capture XHR/Fetch/WebSocket requests made by the page."""
        rtype = request.resource_type
        if rtype in ("xhr", "fetch", "websocket"):
            api_calls.append(InterceptedRequest(
                url=request.url,
                method=request.method,
                resource_type=rtype,
                post_data=request.post_data,
                headers=dict(request.headers) if request.headers else {},
            ))
        # Also capture document/script requests to API-like URLs
        elif rtype in ("document", "script"):
            parsed = urlparse(request.url)
            if re.search(r"/api/|/graphql|/v\d+/|\.json$", parsed.path, re.I):
                api_calls.append(InterceptedRequest(
                    url=request.url,
                    method=request.method,
                    resource_type=f"{rtype}_api",
                ))

    def _on_console(self, msg, result: BrowserCrawlResult):
        """Capture console errors (useful for detecting JS issues)."""
        if msg.type in ("error", "warning"):
            result.console_errors.append(f"[{msg.type}] {msg.text[:300]}")

    # ── SPA detection ─────────────────────────────────────────────────────

    @staticmethod
    def _detect_spa(html: str) -> List[str]:
        """Detect SPA frameworks from the rendered DOM."""
        detected: List[str] = []
        for framework, patterns in SPA_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    detected.append(framework)
                    break
        return detected

    # ── Helpers ───────────────────────────────────────────────────────────

    def _normalise(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl().rstrip("/")

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.target_domain

    @property
    def all_api_calls(self) -> List[InterceptedRequest]:
        """All API calls intercepted across all pages."""
        return list(self._api_calls)

    # ── Event emission ────────────────────────────────────────────────────

    async def _emit(self, event_type: str, message: str, details: Optional[dict] = None):
        logger.info("[BROWSER] %s", message)
        if self.on_event:
            await self.on_event({
                "agent": "BROWSER",
                "event_type": event_type,
                "message": message,
                "details": details or {},
            })
