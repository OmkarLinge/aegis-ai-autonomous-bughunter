"""
Aegis AI — Reconnaissance Agent
Discovers the full attack surface of the target application.
Combines web crawling, common path discovery, technology detection,
site-graph construction, and attack surface mapping.
"""
import asyncio
from typing import Any, List, Dict, Optional, Callable
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from scanner.crawler import Crawler, CommonPathDiscovery, DiscoveredEndpoint
from scanner.request_engine import RequestEngine
from scanner.site_graph import (
    SiteGraph, AttackSurface, RobotsSitemapParser, TechFingerprinter,
)
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
    site_graph: Optional[Any] = None             # SiteGraph instance
    attack_surface: Optional[Any] = None         # AttackSurface instance
    baseline_headers: Dict[str, str] = field(default_factory=dict)


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

        # Build SiteGraph for this scan
        site_graph = SiteGraph(self.target_url)

        # ── Phase 0: Robots.txt & Sitemap Discovery ─────────────────────
        await self._emit("ROBOTS_START", "Parsing robots.txt and sitemap.xml...")
        result.agent_reasoning.append("Phase 0: Parsing robots.txt and sitemap.xml for extra URLs")

        robots_parser = RobotsSitemapParser(self.target_url)
        robots_data = await robots_parser.parse_robots(self.engine)
        extra_urls: List[str] = []

        for path in robots_data.get("disallowed", []):
            if path and not path.startswith("*"):
                from urllib.parse import urljoin
                extra_urls.append(urljoin(self.target_url, path))

        for sitemap_url in robots_data.get("sitemaps", []):
            sitemap_urls = await robots_parser.parse_sitemap(self.engine, sitemap_url)
            extra_urls.extend(sitemap_urls)

        # Also try default sitemap.xml
        if not robots_data.get("sitemaps"):
            sitemap_urls = await robots_parser.parse_sitemap(self.engine)
            extra_urls.extend(sitemap_urls)

        result.agent_reasoning.append(
            f"Robots/sitemap discovery yielded {len(extra_urls)} additonal URLs"
        )

        # ── Phase 0b: Baseline request for WAF / tech fingerprint ───────
        baseline_resp = await self.engine.get(self.target_url)
        if baseline_resp and not baseline_resp.error:
            result.baseline_headers = dict(baseline_resp.headers)
            # Enhanced tech fingerprinting from headers + body
            fp_techs = TechFingerprinter.fingerprint(
                headers=baseline_resp.headers,
                body=baseline_resp.body,
            )
            for tech in fp_techs:
                site_graph.add_technology(tech)

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

        # Populate SiteGraph from crawl results
        for ep in crawl_result.endpoints:
            site_graph.add_endpoint(
                url=ep.url,
                path=ep.path,
                method=ep.method,
                status_code=ep.status_code,
                content_type=ep.content_type,
                depth=ep.depth,
                parameters=ep.parameters,
                forms=ep.forms,
                technologies=ep.technologies,
            )
            # Build edges from parent → child (links discovered on the page)
            for link_url in getattr(ep, "links", []):
                from urllib.parse import urlparse
                link_path = urlparse(link_url).path or "/"
                site_graph.add_link(ep.path, link_path, link_type="navigation")

        await self._emit(
            "CRAWL_COMPLETE",
            f"Crawl found {len(crawl_result.endpoints)} endpoints",
            {"endpoint_count": len(crawl_result.endpoints)},
        )
        result.agent_reasoning.append(
            f"Crawl completed: {len(crawl_result.endpoints)} endpoints, "
            f"technologies: {', '.join(crawl_result.technologies) or 'none detected'}"
        )

        # ── Phase 1b: Queue robots/sitemap URLs into crawl ──────────────
        crawled_paths = {e.path for e in result.endpoints}
        robots_added = 0
        for url in extra_urls:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.path and parsed.path not in crawled_paths:
                resp = await self.engine.get(url, allow_redirects=False)
                if resp and resp.status_code not in (0, 404):
                    ep = DiscoveredEndpoint(
                        url=url,
                        path=parsed.path,
                        method="GET",
                        status_code=resp.status_code,
                        response_time_ms=resp.response_time_ms,
                        content_type=resp.content_type,
                        depth=0,
                    )
                    result.endpoints.append(ep)
                    site_graph.add_endpoint(
                        url=url, path=parsed.path,
                        status_code=resp.status_code,
                        content_type=resp.content_type,
                    )
                    crawled_paths.add(parsed.path)
                    robots_added += 1
                    if robots_added >= 30:
                        break

        if robots_added > 0:
            result.agent_reasoning.append(
                f"Robots/sitemap discovery added {robots_added} new endpoints"
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
        new_common = [e for e in common_endpoints if e.path not in crawled_paths]
        result.endpoints.extend(new_common)
        result.common_paths_found = len(new_common)

        # Add to SiteGraph
        for ep in new_common:
            site_graph.add_endpoint(
                url=ep.url, path=ep.path,
                method=ep.method,
                status_code=ep.status_code,
                content_type=ep.content_type,
            )

        await self._emit(
            "PROBE_COMPLETE",
            f"Common path discovery found {len(new_common)} additional endpoints",
        )

        # ── Phase 3: Build Attack Surface Map ──────────────────────────────
        result.agent_reasoning.append("Phase 3: Building attack surface map from site graph")

        attack_surface = site_graph.build_attack_surface()
        result.site_graph = site_graph
        result.attack_surface = attack_surface

        # Merge SiteGraph technologies into result
        for tech in site_graph.technologies:
            if tech not in result.technologies:
                result.technologies.append(tech)

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

        result.agent_reasoning.append(
            f"Site graph: {site_graph.node_count} nodes, {site_graph.edge_count} edges | "
            f"Attack surface: {attack_surface.total_params} params, {attack_surface.total_forms} forms"
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
