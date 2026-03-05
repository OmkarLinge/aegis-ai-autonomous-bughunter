"""
Aegis AI — JavaScript Endpoint Extractor

Extracts API endpoints from JavaScript source code by detecting:
- fetch() calls
- axios / axios.get / axios.post / ... calls
- XMLHttpRequest .open() calls
- jQuery $.ajax / $.get / $.post calls
- GraphQL query strings and endpoints
- Hardcoded URL strings in JS bundles
- URL patterns in webpack / Vite chunk files

Also parses intercepted network requests from the BrowserCrawler
to produce a unified list of discovered API endpoints.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "JS-EXTRACT")


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class JSEndpoint:
    """An API endpoint discovered in JavaScript source code."""
    url: str
    method: str = "GET"                         # GET | POST | PUT | DELETE | PATCH | UNKNOWN
    source: str = "js_static"                   # js_static | network_intercept | graphql | url_string
    context: str = ""                           # fetch | axios | xhr | jquery | graphql | string_literal
    parameters: List[str] = field(default_factory=list)
    graphql_operation: str = ""                  # query | mutation | subscription
    graphql_name: str = ""
    confidence: float = 0.7
    raw_snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "url": self.url,
            "method": self.method,
            "source": self.source,
            "context": self.context,
            "confidence": self.confidence,
        }
        if self.parameters:
            d["parameters"] = self.parameters
        if self.graphql_operation:
            d["graphql_operation"] = self.graphql_operation
            d["graphql_name"] = self.graphql_name
        return d


@dataclass
class JSExtractionResult:
    """Complete extraction result for a scan."""
    endpoints: List[JSEndpoint] = field(default_factory=list)
    graphql_detected: bool = False
    total_scripts_parsed: int = 0
    total_network_requests: int = 0

    @property
    def api_endpoint_count(self) -> int:
        return len([e for e in self.endpoints if e.source != "graphql"])

    @property
    def graphql_operation_count(self) -> int:
        return len([e for e in self.endpoints if e.source == "graphql"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_endpoints": len(self.endpoints),
            "api_endpoints": self.api_endpoint_count,
            "graphql_operations": self.graphql_operation_count,
            "graphql_detected": self.graphql_detected,
            "scripts_parsed": self.total_scripts_parsed,
            "network_requests": self.total_network_requests,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


# ── Extraction patterns ─────────────────────────────────────────────────────

# fetch("url") / fetch(`url`) / fetch(URL, { method: "POST" })
FETCH_PATTERNS = [
    # fetch("url") or fetch('url') or fetch(`url`)
    re.compile(
        r"""\bfetch\s*\(\s*['"`]([^'"`\s]+)['"`]"""
        r"""(?:\s*,\s*\{[^}]*?method\s*:\s*['"`](\w+)['"`])?""",
        re.I | re.DOTALL,
    ),
    # fetch(variable) — capture the variable name as a hint
    re.compile(
        r"""\bfetch\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*[,)]""",
        re.I,
    ),
]

# axios.get/post/put/delete/patch("url")
AXIOS_PATTERNS = [
    re.compile(
        r"""\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.I,
    ),
    # axios("url") or axios({ url: "...", method: "..." })
    re.compile(
        r"""\baxios\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.I,
    ),
    re.compile(
        r"""\baxios\s*\(\s*\{[^}]*?url\s*:\s*['"`]([^'"`]+)['"`]"""
        r"""[^}]*?method\s*:\s*['"`](\w+)['"`]""",
        re.I | re.DOTALL,
    ),
]

# XMLHttpRequest .open("METHOD", "url")
XHR_PATTERN = re.compile(
    r"""\.open\s*\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
    re.I,
)

# jQuery $.ajax, $.get, $.post, $.getJSON
JQUERY_PATTERNS = [
    re.compile(
        r"""\$\s*\.\s*(get|post|getJSON|ajax)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.I,
    ),
    re.compile(
        r"""\$\s*\.\s*ajax\s*\(\s*\{[^}]*?url\s*:\s*['"`]([^'"`]+)['"`]"""
        r"""[^}]*?(?:type|method)\s*:\s*['"`](\w+)['"`]""",
        re.I | re.DOTALL,
    ),
]

# GraphQL — query strings
GRAPHQL_PATTERNS = [
    # query { ... } or mutation { ... }
    re.compile(
        r"""\b(query|mutation|subscription)\s+(\w+)?\s*(?:\([^)]*\))?\s*\{""",
        re.I,
    ),
    # gql`` or graphql`` tagged template literals
    re.compile(
        r"""\b(?:gql|graphql)\s*`\s*(query|mutation|subscription)\s+(\w+)?""",
        re.I,
    ),
]

# Hardcoded URL patterns in JS bundles (REST-like paths)
URL_STRING_PATTERN = re.compile(
    r"""['"`]((?:https?://[^'"`\s]{5,200})|(?:/api/[^'"`\s]{2,200})|(?:/v[1-9]/[^'"`\s]{2,200})|(?:/graphql[^'"`\s]{0,100}))['"`]""",
    re.I,
)

# HTTP method assignment in config objects
METHOD_IN_CONFIG = re.compile(
    r"""(?:method|type)\s*:\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]""",
    re.I,
)

# URL path parameters like /users/:id or /users/{id}
PATH_PARAM_PATTERN = re.compile(r"""[:{}]([a-zA-Z_][a-zA-Z0-9_]*)""")


class JSEndpointExtractor:
    """
    Extracts API endpoints from JavaScript source code and
    network interceptions.

    Usage::

        extractor = JSEndpointExtractor(base_url="https://example.com")
        result = extractor.extract_from_scripts(
            js_sources=["inline:fetch('/api/users')..."],
        )
        # Or combine with network interceptions:
        result = extractor.extract_all(
            js_sources=[...],
            intercepted_requests=[...],
        )
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self._seen_urls: Set[str] = set()

    def extract_all(
        self,
        js_sources: Optional[List[str]] = None,
        intercepted_requests: Optional[List[Any]] = None,
    ) -> JSExtractionResult:
        """
        Extract endpoints from both JS source code and network interceptions.

        Args:
            js_sources: list of script contents / URLs from BrowserCrawler
            intercepted_requests: list of InterceptedRequest from BrowserCrawler
        """
        result = JSExtractionResult()

        # ── Extract from JS source code ─────────────────────────────────
        if js_sources:
            self._extract_from_scripts(js_sources, result)

        # ── Extract from network interceptions ──────────────────────────
        if intercepted_requests:
            self._extract_from_network(intercepted_requests, result)

        # ── Deduplicate ─────────────────────────────────────────────────
        result.endpoints = self._deduplicate(result.endpoints)

        logger.info(
            "[JS-EXTRACT] Complete: %d endpoints (%d API, %d GraphQL) "
            "from %d scripts + %d network requests",
            len(result.endpoints), result.api_endpoint_count,
            result.graphql_operation_count, result.total_scripts_parsed,
            result.total_network_requests,
        )

        return result

    # ── JS source extraction ──────────────────────────────────────────────

    def _extract_from_scripts(
        self,
        js_sources: List[str],
        result: JSExtractionResult,
    ):
        """Parse JavaScript source code for API endpoints."""
        for src in js_sources:
            # Get the code content
            if src.startswith("inline:"):
                code = src[7:]
            elif src.startswith("http"):
                # We don't have the content of external scripts here
                # They would need to be fetched separately
                continue
            else:
                code = src

            if not code or len(code.strip()) < 10:
                continue

            result.total_scripts_parsed += 1

            # ── fetch() ─────────────────────────────────────────────
            for pattern in FETCH_PATTERNS:
                for match in pattern.finditer(code):
                    groups = match.groups()
                    url_str = groups[0]
                    method = groups[1].upper() if len(groups) > 1 and groups[1] else "GET"

                    if self._is_url_like(url_str):
                        ep = self._build_endpoint(
                            url_str, method, "fetch",
                            snippet=match.group(0)[:200],
                        )
                        if ep:
                            result.endpoints.append(ep)

            # ── axios ───────────────────────────────────────────────
            for pattern in AXIOS_PATTERNS:
                for match in pattern.finditer(code):
                    groups = match.groups()
                    if len(groups) == 2:
                        # axios.get("url") pattern
                        method = groups[0].upper()
                        url_str = groups[1]
                    else:
                        url_str = groups[0]
                        method = groups[1].upper() if len(groups) > 1 and groups[1] else "GET"

                    if self._is_url_like(url_str):
                        ep = self._build_endpoint(
                            url_str, method, "axios",
                            snippet=match.group(0)[:200],
                        )
                        if ep:
                            result.endpoints.append(ep)

            # ── XMLHttpRequest ──────────────────────────────────────
            for match in XHR_PATTERN.finditer(code):
                method = match.group(1).upper()
                url_str = match.group(2)
                if self._is_url_like(url_str):
                    ep = self._build_endpoint(
                        url_str, method, "xhr",
                        snippet=match.group(0)[:200],
                    )
                    if ep:
                        result.endpoints.append(ep)

            # ── jQuery ──────────────────────────────────────────────
            for pattern in JQUERY_PATTERNS:
                for match in pattern.finditer(code):
                    groups = match.groups()
                    if len(groups) == 2 and groups[0].lower() != "ajax":
                        jquery_method = groups[0].lower()
                        url_str = groups[1]
                        method = "POST" if jquery_method == "post" else "GET"
                    elif len(groups) == 2:
                        url_str = groups[0]
                        method = groups[1].upper() if groups[1] else "GET"
                    else:
                        url_str = groups[0]
                        method = "GET"

                    if self._is_url_like(url_str):
                        ep = self._build_endpoint(
                            url_str, method, "jquery",
                            snippet=match.group(0)[:200],
                        )
                        if ep:
                            result.endpoints.append(ep)

            # ── GraphQL ─────────────────────────────────────────────
            for pattern in GRAPHQL_PATTERNS:
                for match in pattern.finditer(code):
                    op_type = match.group(1).lower()
                    op_name = match.group(2) or "anonymous"
                    result.graphql_detected = True
                    result.endpoints.append(JSEndpoint(
                        url=f"{self.base_url}/graphql",
                        method="POST",
                        source="graphql",
                        context="graphql",
                        graphql_operation=op_type,
                        graphql_name=op_name,
                        confidence=0.8,
                        raw_snippet=match.group(0)[:200],
                    ))

            # ── Hardcoded URL strings ───────────────────────────────
            for match in URL_STRING_PATTERN.finditer(code):
                url_str = match.group(1)
                if self._is_url_like(url_str) and not self._is_static(url_str):
                    # Try to detect method from nearby code
                    nearby = code[max(0, match.start() - 100):match.end() + 100]
                    method_match = METHOD_IN_CONFIG.search(nearby)
                    method = method_match.group(1).upper() if method_match else "UNKNOWN"

                    ep = self._build_endpoint(
                        url_str, method, "string_literal",
                        snippet=match.group(0)[:200],
                        confidence=0.5,
                    )
                    if ep:
                        result.endpoints.append(ep)

    # ── Network interception extraction ───────────────────────────────────

    def _extract_from_network(
        self,
        requests: List[Any],
        result: JSExtractionResult,
    ):
        """Convert intercepted network requests to JSEndpoints."""
        for req in requests:
            result.total_network_requests += 1
            url = getattr(req, "url", "") or req.get("url", "") if isinstance(req, dict) else req.url
            method = getattr(req, "method", "GET") if not isinstance(req, dict) else req.get("method", "GET")
            rtype = getattr(req, "resource_type", "") if not isinstance(req, dict) else req.get("resource_type", "")

            if not url:
                continue

            # Skip non-API requests
            parsed = urlparse(url)
            is_api = rtype in ("xhr", "fetch") or re.search(
                r"/api/|/graphql|/v\d+/|\.json$", parsed.path, re.I
            )
            if not is_api:
                continue

            # Check if GraphQL
            is_graphql = "graphql" in parsed.path.lower()

            ep = JSEndpoint(
                url=url,
                method=method.upper(),
                source="network_intercept",
                context="graphql" if is_graphql else rtype,
                confidence=0.95,  # Network intercepts are high confidence
            )

            # Extract query parameters as endpoint parameters
            if parsed.query:
                from urllib.parse import parse_qs
                ep.parameters = list(parse_qs(parsed.query).keys())

            if is_graphql:
                ep.graphql_operation = "query"
                result.graphql_detected = True

            result.endpoints.append(ep)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _build_endpoint(
        self,
        url_str: str,
        method: str,
        context: str,
        snippet: str = "",
        confidence: float = 0.7,
    ) -> Optional[JSEndpoint]:
        """Build a JSEndpoint from extracted URL string."""
        # Resolve relative URLs
        if url_str.startswith("/"):
            full_url = urljoin(self.base_url, url_str)
        elif url_str.startswith("http"):
            full_url = url_str
        else:
            # Might be a variable name or relative path
            return None

        # Filter out non-same-domain URLs
        parsed = urlparse(full_url)
        if parsed.netloc and parsed.netloc != self.base_domain:
            return None

        # Skip if already seen
        normalised = parsed._replace(fragment="", query="").geturl()
        if normalised in self._seen_urls:
            return None
        self._seen_urls.add(normalised)

        # Extract path parameters
        params = PATH_PARAM_PATTERN.findall(parsed.path)

        # Extract query parameters
        if parsed.query:
            from urllib.parse import parse_qs
            params.extend(parse_qs(parsed.query).keys())

        return JSEndpoint(
            url=full_url,
            method=method,
            source="js_static",
            context=context,
            parameters=params,
            confidence=confidence,
            raw_snippet=snippet,
        )

    @staticmethod
    def _is_url_like(s: str) -> bool:
        """Check if a string looks like a URL or API path."""
        if not s or len(s) < 2:
            return False
        # Must start with / or http
        if not (s.startswith("/") or s.startswith("http")):
            return False
        # Skip common false positives
        if s in ("/", "//", "/#", "/*"):
            return False
        # Skip template literals that are just variables
        if "${" in s and "/" not in s.split("${")[0]:
            return False
        return True

    @staticmethod
    def _is_static(url: str) -> bool:
        """Check if URL points to a static asset."""
        return bool(re.search(
            r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp[34]|pdf|map)(\?|$)",
            url, re.I,
        ))

    def _deduplicate(self, endpoints: List[JSEndpoint]) -> List[JSEndpoint]:
        """Remove duplicate endpoints, keeping highest confidence."""
        seen: Dict[str, JSEndpoint] = {}
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen or ep.confidence > seen[key].confidence:
                seen[key] = ep
        return list(seen.values())
