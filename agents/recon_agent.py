"""
Aegis AI — Reconnaissance Agent
Discovers the full attack surface of the target application.
Combines web crawling, common path discovery, and technology detection.
"""
import asyncio
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from scanner.crawler import Crawler, CommonPathDiscovery, DiscoveredEndpoint
from scanner.request_engine import RequestEngine
from utils.logger import get_logger, log_agent_event

logger = get_logger(__name__, "RECON")


@dataclass
class ReconResult:
    """Complete result from the Recon Agent."""
    target_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    forms_found: int = 0
    params_found: int = 0
    common_paths_found: int = 0
    scan_duration_ms: float = 0.0
    agent_reasoning: List[str] = field(default_factory=list)


class ReconAgent:
    """
    Reconnaissance Agent — discovers the attack surface.

    Phase 1: Crawl the target from the root URL
    Phase 2: Probe common paths (admin panels, API routes, etc.)
    Phase 3: Analyze discovered endpoints for interesting patterns
    Phase 4: Summarize findings for the Strategy Agent
    """

    def __init__(
        self,
        target_url: str,
        authorized: bool = False,
        max_depth: int = 3,
        on_event: Optional[Callable] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.authorized = authorized
        self.max_depth = max_depth
        self.on_event = on_event
        self.engine = RequestEngine(target_url, authorized)

    async def _emit(self, event_type: str, message: str, details: dict = None):
        """Emit an agent event for real-time dashboard updates."""
        log_agent_event(logger, event_type, details or {})
        if self.on_event:
            await self.on_event({
                "agent": "RECON",
                "event_type": event_type,
                "message": message,
                "details": details or {},
            })

    async def run(self) -> ReconResult:
        """Execute the full reconnaissance phase."""
        import time
        start = time.monotonic()

        result = ReconResult(target_url=self.target_url)
        result.agent_reasoning.append(
            f"Starting reconnaissance on {self.target_url}"
        )

        await self._emit("START", f"Recon Agent initialized for {self.target_url}")

        # ── Phase 1: Initial Crawl ──────────────────────────────────────────
        await self._emit("CRAWL_START", "Beginning web crawl...")
        result.agent_reasoning.append("Phase 1: Crawling website to discover linked pages")

        crawler = Crawler(
            target_url=self.target_url,
            request_engine=self.engine,
            max_depth=self.max_depth,
            on_endpoint_discovered=self._on_endpoint_found,
        )

        crawl_result = await crawler.crawl()
        result.endpoints.extend(crawl_result.endpoints)
        result.technologies = crawl_result.technologies

        await self._emit(
            "CRAWL_COMPLETE",
            f"Crawl found {len(crawl_result.endpoints)} endpoints",
            {"endpoint_count": len(crawl_result.endpoints)},
        )
        result.agent_reasoning.append(
            f"Crawl completed: {len(crawl_result.endpoints)} endpoints, "
            f"technologies: {', '.join(crawl_result.technologies) or 'none detected'}"
        )

        # ── Phase 2: Common Path Discovery ─────────────────────────────────
        await self._emit("PROBE_START", "Probing common paths and admin panels...")
        result.agent_reasoning.append("Phase 2: Probing well-known paths (/admin, /api, etc.)")

        common_discovery = CommonPathDiscovery()
        common_endpoints = await common_discovery.discover(
            self.target_url,
            self.engine,
            callback=self._on_endpoint_found,
        )

        # Deduplicate against crawled endpoints
        crawled_paths = {e.path for e in result.endpoints}
        new_common = [e for e in common_endpoints if e.path not in crawled_paths]
        result.endpoints.extend(new_common)
        result.common_paths_found = len(new_common)

        await self._emit(
            "PROBE_COMPLETE",
            f"Common path discovery found {len(new_common)} additional endpoints",
        )

        # ── Phase 3: Analyze Endpoints ──────────────────────────────────────
        result.agent_reasoning.append("Phase 3: Analyzing discovered endpoints")

        # Count interesting findings
        for ep in result.endpoints:
            result.forms_found += len(ep.forms)
            result.params_found += len(ep.parameters)

        # Identify high-value endpoints for the exploit agent
        high_value = self._identify_high_value_endpoints(result.endpoints)
        result.agent_reasoning.append(
            f"High-value endpoints identified: {len(high_value)} "
            f"(auth={sum(1 for e in high_value if e.endpoint_type == 'authentication')}, "
            f"upload={sum(1 for e in high_value if e.endpoint_type == 'file_upload')}, "
            f"admin={sum(1 for e in high_value if e.endpoint_type == 'admin_panel')})"
        )

        result.scan_duration_ms = (time.monotonic() - start) * 1000

        await self._emit(
            "COMPLETE",
            f"Reconnaissance complete: {len(result.endpoints)} endpoints discovered",
            {
                "total_endpoints": len(result.endpoints),
                "forms": result.forms_found,
                "parameters": result.params_found,
                "technologies": len(result.technologies),
            },
        )

        logger.info(
            f"[RECON] Complete | endpoints={len(result.endpoints)} "
            f"forms={result.forms_found} params={result.params_found} "
            f"time={result.scan_duration_ms:.0f}ms"
        )
        return result

    def _identify_high_value_endpoints(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DiscoveredEndpoint]:
        """Score and identify endpoints most likely to have vulnerabilities."""
        from utils.config import ENDPOINT_PATTERNS
        import re

        high_value = []
        for ep in endpoints:
            for category, patterns in ENDPOINT_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, ep.path, re.IGNORECASE):
                        ep.endpoint_type = category
                        high_value.append(ep)
                        break
                else:
                    continue
                break

        return high_value

    async def _on_endpoint_found(self, endpoint: DiscoveredEndpoint):
        """Callback invoked when an endpoint is discovered."""
        await self._emit(
            "ENDPOINT_FOUND",
            f"Discovered: {endpoint.path} [{endpoint.status_code}]",
            {
                "path": endpoint.path,
                "status_code": endpoint.status_code,
                "method": endpoint.method,
                "forms": len(endpoint.forms),
            },
        )
