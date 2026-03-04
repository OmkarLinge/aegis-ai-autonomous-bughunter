"""
Aegis AI — Web Crawler
Discovers endpoints, forms, parameters, and technologies on target websites.
Forms the foundation of the reconnaissance phase.
"""
import asyncio
import re
from typing import Set, List, Dict, Optional, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from scanner.request_engine import RequestEngine, HttpResponse
from utils.config import config
from utils.logger import get_logger

logger = get_logger(__name__, "RECON")


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint with all its metadata."""
    url: str
    path: str
    method: str = "GET"
    status_code: int = 0
    response_time_ms: float = 0.0
    content_type: str = ""
    parameters: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    depth: int = 0
    endpoint_type: str = "unknown"


@dataclass
class CrawlResult:
    """Complete result of a crawl operation."""
    target_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    total_links_found: int = 0
    crawl_duration_ms: float = 0.0


class TechnologyDetector:
    """Detects web technologies from HTTP responses."""

    SIGNATURES = {
        "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal": [r"Drupal\.settings", r"/sites/default/files"],
        "Joomla": [r"Joomla!", r"/components/com_"],
        "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "Laravel": [r"laravel_session", r"Laravel"],
        "React": [r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react-root", r"data-reactroot"],
        "Angular": [r"ng-app", r"ng-controller", r"angular\.js"],
        "Vue.js": [r"__vue__", r"v-app", r"vue\.js"],
        "jQuery": [r"jquery", r"jQuery"],
        "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.js"],
        "Express": [r"X-Powered-By.*Express"],
        "ASP.NET": [r"__VIEWSTATE", r"asp\.net", r"ASP\.NET"],
        "PHP": [r"\.php", r"X-Powered-By.*PHP"],
        "Python": [r"X-Powered-By.*Python", r"Django", r"Flask"],
        "Ruby on Rails": [r"X-Runtime", r"X-Powered-By.*Phusion Passenger"],
        "Nginx": [r"Server.*nginx"],
        "Apache": [r"Server.*Apache"],
        "Cloudflare": [r"CF-RAY", r"cloudflare"],
        "GraphQL": [r"graphql", r"__schema", r"__typename"],
    }

    def detect(self, response: HttpResponse) -> List[str]:
        """Detect technologies from response headers and body."""
        detected = set()
        content = response.body.lower()
        headers_str = str(response.headers).lower()
        combined = content + headers_str

        for tech, patterns in self.SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(tech)
                    break

        return sorted(detected)


class FormExtractor:
    """Extracts HTML forms and their fields."""

    def extract(self, base_url: str, html: str) -> List[Dict]:
        """Extract all forms with their inputs and action URLs."""
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(base_url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                    "has_file_upload": False,
                    "has_password": False,
                }

                for inp in form.find_all(["input", "textarea", "select"]):
                    input_data = {
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                        "required": inp.has_attr("required"),
                    }
                    if input_data["name"]:
                        form_data["inputs"].append(input_data)
                    if input_data["type"] == "file":
                        form_data["has_file_upload"] = True
                    if input_data["type"] == "password":
                        form_data["has_password"] = True

                forms.append(form_data)
        except Exception as e:
            logger.debug(f"Form extraction error: {e}")
        return forms


class ParameterExtractor:
    """Extracts URL parameters and API patterns."""

    def extract_from_url(self, url: str) -> List[Dict]:
        """Extract parameters from URL query string."""
        parsed = urlparse(url)
        params = []
        for key, values in parse_qs(parsed.query).items():
            params.append({
                "name": key,
                "value": values[0] if values else "",
                "source": "url",
            })
        return params

    def extract_from_html(self, html: str) -> List[str]:
        """Extract potential API parameter names from JavaScript."""
        # Look for common parameter patterns in JS code
        patterns = [
            r'"([a-z_][a-z0-9_]{1,30})"\s*:', # JSON key patterns
            r'data\["([a-z_][a-z0-9_]{1,30})"\]', # data["param"]
            r'params\.([a-z_][a-z0-9_]{1,30})', # params.name
        ]
        found = set()
        for pattern in patterns:
            found.update(re.findall(pattern, html, re.IGNORECASE))
        # Filter out common JS keywords
        blacklist = {"type", "name", "value", "class", "id", "src", "href",
                     "for", "var", "let", "const", "function", "return"}
        return [p for p in found if p.lower() not in blacklist]


class Crawler:
    """
    Asynchronous web crawler for endpoint discovery.

    Uses a BFS approach to crawl the target website up to the configured depth,
    discovering all reachable endpoints, forms, and parameters.
    """

    def __init__(
        self,
        target_url: str,
        request_engine: RequestEngine,
        max_depth: int = None,
        max_endpoints: int = None,
        on_endpoint_discovered: Optional[Callable] = None,
    ):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.engine = request_engine
        self.max_depth = max_depth or config.scan.max_depth
        self.max_endpoints = max_endpoints or config.scan.max_endpoints
        self.on_endpoint_discovered = on_endpoint_discovered

        self._visited: Set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()

        self.tech_detector = TechnologyDetector()
        self.form_extractor = FormExtractor()
        self.param_extractor = ParameterExtractor()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicate visits."""
        parsed = urlparse(url)
        # Remove fragment, normalize path
        normalized = parsed._replace(fragment="")
        return normalized.geturl()

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        """Extract all same-domain links from HTML."""
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["a", "link", "script", "form"]):
                href = tag.get("href") or tag.get("src") or tag.get("action", "")
                if not href:
                    continue
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)

                # Only follow same-domain links
                if parsed.netloc == self.base_domain or parsed.netloc == "":
                    # Skip non-HTTP links
                    if parsed.scheme in ("http", "https", ""):
                        links.append(full_url)
        except Exception as e:
            logger.debug(f"Link extraction error: {e}")
        return links

    def _extract_api_routes(self, html: str, base_url: str) -> List[str]:
        """Extract API routes from JavaScript code."""
        routes = []
        # Common patterns for API route definitions
        patterns = [
            r'(?:fetch|axios\.get|axios\.post|http\.get|http\.post)\s*\(\s*[\'"]([/a-zA-Z0-9_\-\.]+)[\'"]',
            r'(?:url|endpoint|path|route)\s*[=:]\s*[\'"]([/][a-zA-Z0-9_\-\./]+)[\'"]',
            r'[\'"]([/]api[/][a-zA-Z0-9_\-\./]+)[\'"]',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if match.startswith("/"):
                    routes.append(urljoin(base_url, match))
        return list(set(routes))

    async def crawl(self) -> CrawlResult:
        """
        Perform the full crawl operation.

        Returns:
            CrawlResult with all discovered endpoints and metadata.
        """
        import time
        start_time = time.monotonic()

        result = CrawlResult(target_url=self.target_url)
        all_technologies: Set[str] = set()

        logger.info(f"Starting crawl of {self.target_url} (depth={self.max_depth})")

        # Seed the queue with the target URL
        await self._queue.put((self.target_url, 0))

        while not self._queue.empty() and len(result.endpoints) < self.max_endpoints:
            url, depth = await self._queue.get()
            normalized = self._normalize_url(url)

            if normalized in self._visited or depth > self.max_depth:
                continue
            self._visited.add(normalized)

            # Fetch the page
            logger.debug(f"Crawling: {url} (depth={depth})")
            response = await self.engine.get(url)

            if response.error and response.status_code == 0:
                continue

            # Build endpoint object
            parsed_url = urlparse(url)
            endpoint = DiscoveredEndpoint(
                url=url,
                path=parsed_url.path or "/",
                method="GET",
                status_code=response.status_code,
                response_time_ms=response.response_time_ms,
                content_type=response.content_type,
                parameters=self.param_extractor.extract_from_url(url),
                depth=depth,
            )

            # Detect technologies
            techs = self.tech_detector.detect(response)
            endpoint.technologies = techs
            all_technologies.update(techs)

            # Extract forms
            if response.is_html:
                endpoint.forms = self.form_extractor.extract(url, response.body)

                # Extract links and queue for crawling
                links = self._extract_links(url, response.body)
                result.total_links_found += len(links)
                endpoint.links = links[:20]  # Store sample

                # Queue discovered links for crawling
                if depth < self.max_depth:
                    for link in links:
                        norm_link = self._normalize_url(link)
                        if norm_link not in self._visited:
                            await self._queue.put((link, depth + 1))

                # Extract API routes from JS
                api_routes = self._extract_api_routes(response.body, url)
                for route in api_routes:
                    norm_route = self._normalize_url(route)
                    if norm_route not in self._visited:
                        await self._queue.put((route, depth + 1))

            result.endpoints.append(endpoint)

            # Fire callback for live updates
            if self.on_endpoint_discovered:
                try:
                    await self.on_endpoint_discovered(endpoint)
                except Exception:
                    pass

        result.technologies = sorted(all_technologies)
        result.crawl_duration_ms = (time.monotonic() - start_time) * 1000

        logger.info(
            f"Crawl complete: {len(result.endpoints)} endpoints, "
            f"{len(result.technologies)} technologies, "
            f"{result.crawl_duration_ms:.0f}ms"
        )
        return result


class CommonPathDiscovery:
    """
    Discovers common paths by probing well-known URLs.
    Used when crawling has limited reach (JavaScript-heavy apps).
    """

    COMMON_PATHS = [
        "/admin", "/admin/login", "/admin/dashboard",
        "/api", "/api/v1", "/api/v2", "/api/users",
        "/api/login", "/api/auth", "/api/health",
        "/login", "/logout", "/register", "/signin", "/signup",
        "/forgot-password", "/reset-password",
        "/upload", "/files", "/media", "/static",
        "/dashboard", "/profile", "/settings", "/account",
        "/search", "/sitemap.xml", "/robots.txt",
        "/.well-known/security.txt",
        "/wp-admin", "/wp-login.php",  # WordPress
        "/phpmyadmin", "/phpinfo.php",
        "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql",
        "/.git/config", "/.env", "/config.json",  # Sensitive files
        "/backup", "/backup.zip", "/db.sql",
    ]

    async def discover(
        self,
        target_url: str,
        engine: RequestEngine,
        callback: Optional[Callable] = None,
    ) -> List[DiscoveredEndpoint]:
        """Probe common paths on the target."""
        discovered = []
        tasks = []

        for path in self.COMMON_PATHS:
            url = urljoin(target_url, path)
            tasks.append(self._probe(url, path, engine))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for endpoint in results:
            if isinstance(endpoint, DiscoveredEndpoint):
                if endpoint.status_code not in (404, 0, 403):
                    discovered.append(endpoint)
                    if callback:
                        try:
                            await callback(endpoint)
                        except Exception:
                            pass

        return discovered

    async def _probe(
        self, url: str, path: str, engine: RequestEngine
    ) -> DiscoveredEndpoint:
        """Probe a single path."""
        response = await engine.get(url, allow_redirects=False)
        return DiscoveredEndpoint(
            url=url,
            path=path,
            method="GET",
            status_code=response.status_code,
            response_time_ms=response.response_time_ms,
            content_type=response.content_type,
            depth=0,
        )
