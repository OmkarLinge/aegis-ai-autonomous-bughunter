"""
Aegis AI — Site Graph & Attack Surface Mapper

Pillar 1 — Professional Target Mapping

Instead of a flat list of endpoints, builds a directed navigation graph:
    / → /login → /dashboard
    / → /products → /products?id=1
    / → /api/v1 → /api/v1/users

Then extracts a structured Attack Surface Map:
    {
        "authentication": [("/login", ["POST username", "POST password"])],
        "file_upload":    [("/upload", ["POST file"])],
        "api":            [("/api/v1/users", ["GET id", "DELETE id"])],
        "search":         [("/search", ["GET query"])],
        ...
    }

This allows all downstream agents to reason about WHERE in the
application each endpoint sits and HOW it relates to others.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "SITEGRAPH")


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class SiteNode:
    """A single node in the site graph."""
    url: str
    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    depth: int = 0
    parameters: List[Dict[str, str]] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    node_type: str = "page"          # page | api | form | static | auth | upload | admin
    has_auth: bool = False
    has_upload: bool = False
    has_search: bool = False
    response_size: int = 0

    @property
    def id(self) -> str:
        """Unique node identifier."""
        return f"{self.method}:{self.path}"

    @property
    def param_names(self) -> List[str]:
        return [p.get("name", "") for p in self.parameters if p.get("name")]


@dataclass
class SiteEdge:
    """A navigation link between two nodes."""
    source_path: str
    target_path: str
    link_type: str = "navigation"    # navigation | form_action | redirect | api_call | js_reference
    label: str = ""


@dataclass
class AttackSurface:
    """Structured attack surface map."""
    authentication: List[Dict[str, Any]] = field(default_factory=list)
    file_upload: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    search_inputs: List[Dict[str, Any]] = field(default_factory=list)
    admin_panels: List[Dict[str, Any]] = field(default_factory=list)
    redirect_params: List[Dict[str, Any]] = field(default_factory=list)
    data_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    static_files: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    total_params: int = 0
    total_forms: int = 0
    total_endpoints: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authentication": self.authentication,
            "file_upload": self.file_upload,
            "api_endpoints": self.api_endpoints,
            "search_inputs": self.search_inputs,
            "admin_panels": self.admin_panels,
            "redirect_params": self.redirect_params,
            "data_endpoints": self.data_endpoints,
            "static_files": self.static_files,
            "forms": self.forms,
            "summary": {
                "total_endpoints": self.total_endpoints,
                "total_params": self.total_params,
                "total_forms": self.total_forms,
                "auth_endpoints": len(self.authentication),
                "upload_endpoints": len(self.file_upload),
                "api_endpoints": len(self.api_endpoints),
                "search_endpoints": len(self.search_inputs),
                "admin_endpoints": len(self.admin_panels),
            },
        }


# ── Classification patterns ─────────────────────────────────────────────────

AUTH_PATTERNS = re.compile(
    r"(log.?in|sign.?in|auth|oauth|sso|register|sign.?up|forgot|reset.?pass|"
    r"session|token|logout|log.?out|2fa|mfa|verify.?email)", re.I
)
UPLOAD_PATTERNS = re.compile(
    r"(upload|attach|import|file|media|image|photo|avatar|document|csv)", re.I
)
SEARCH_PATTERNS = re.compile(
    r"(search|find|query|lookup|filter|autocomplete|suggest|typeahead)", re.I
)
ADMIN_PATTERNS = re.compile(
    r"(admin|dashboard|manage|panel|control|settings|config|moderate|cms|"
    r"back.?office|internal)", re.I
)
API_PATTERNS = re.compile(
    r"(api|graphql|rest|v\d+/|\.json|\.xml|webhook|callback|endpoint)", re.I
)
REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_to", "return", "returnurl", "return_to",
    "next", "url", "goto", "continue", "target", "dest", "destination",
    "rurl", "redir", "redirect_uri", "callback",
}
STATIC_PATTERNS = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp[34]|pdf)(\?|$)", re.I
)

# Technology → template engine payload hints
TECH_PAYLOAD_HINTS: Dict[str, Dict[str, str]] = {
    "flask":   {"ssti_engine": "jinja2", "ssti_probe": "{{7*7}}"},
    "jinja2":  {"ssti_engine": "jinja2", "ssti_probe": "{{7*7}}"},
    "django":  {"ssti_engine": "django", "ssti_probe": "{% debug %}"},
    "express": {"ssti_engine": "ejs",    "ssti_probe": "<%=7*7%>"},
    "php":     {"ssti_engine": "twig",   "ssti_probe": "{{7*7}}"},
    "ruby":    {"ssti_engine": "erb",    "ssti_probe": "<%=7*7%>"},
    "asp.net": {"ssti_engine": "razor",  "ssti_probe": "@(7*7)"},
    "java":    {"ssti_engine": "thymeleaf", "ssti_probe": "${7*7}"},
    "spring":  {"ssti_engine": "thymeleaf", "ssti_probe": "${7*7}"},
}


class SiteGraph:
    """
    Directed graph of the target application.

    Nodes  = endpoints (URL + method)
    Edges  = navigation links / form actions / redirects / JS references

    Provides:
    - ``add_endpoint(...)`` — add nodes during crawl
    - ``add_link(...)`` — add edges during crawl
    - ``build_attack_surface()`` — after crawl, compute structured attack surface
    - ``get_entry_points()`` — high-value nodes for exploit agent
    - ``to_dict()`` — serializeable graph for frontend / reports
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self._nodes: Dict[str, SiteNode] = {}       # path → SiteNode
        self._edges: List[SiteEdge] = []
        self._technologies: Set[str] = set()

    # ── Building the graph ────────────────────────────────────────────────

    def add_endpoint(
        self,
        url: str,
        path: str,
        method: str = "GET",
        status_code: int = 0,
        content_type: str = "",
        depth: int = 0,
        parameters: Optional[List[Dict]] = None,
        forms: Optional[List[Dict]] = None,
        technologies: Optional[List[str]] = None,
        response_size: int = 0,
    ) -> SiteNode:
        """Register an endpoint as a node in the graph."""
        parameters = parameters or []
        forms = forms or []
        technologies = technologies or []

        node_type = self._classify_node(path, parameters, forms)
        has_auth = bool(AUTH_PATTERNS.search(path))
        has_upload = any(f.get("has_file_upload") for f in forms)
        has_search = bool(SEARCH_PATTERNS.search(path)) or any(
            p.get("name", "").lower() in ("q", "query", "search", "keyword")
            for p in parameters
        )

        # Check params for redirect patterns
        param_names_lower = {p.get("name", "").lower() for p in parameters}

        node = SiteNode(
            url=url,
            path=path,
            method=method,
            status_code=status_code,
            content_type=content_type,
            depth=depth,
            parameters=parameters,
            forms=forms,
            technologies=technologies,
            node_type=node_type,
            has_auth=has_auth,
            has_upload=has_upload,
            has_search=has_search,
            response_size=response_size,
        )

        key = node.id
        # Keep the one with more info
        if key in self._nodes:
            existing = self._nodes[key]
            if len(node.parameters) > len(existing.parameters) or len(node.forms) > len(existing.forms):
                self._nodes[key] = node
        else:
            self._nodes[key] = node

        # Track technologies
        for tech in technologies:
            self._technologies.add(tech.lower())

        return node

    def add_link(
        self,
        source_path: str,
        target_path: str,
        link_type: str = "navigation",
        label: str = "",
    ):
        """Add a directed edge from source → target."""
        edge = SiteEdge(
            source_path=source_path,
            target_path=target_path,
            link_type=link_type,
            label=label,
        )
        self._edges.append(edge)

    def add_technology(self, tech: str):
        self._technologies.add(tech.lower())

    # ── Attack Surface Mapping ────────────────────────────────────────────

    def build_attack_surface(self) -> AttackSurface:
        """
        Analyze the graph and produce a structured attack surface map.

        Groups endpoints by function (auth, upload, search, API, admin, etc.)
        and lists parameters per endpoint.
        """
        surface = AttackSurface()
        all_params = 0
        all_forms = 0

        for node in self._nodes.values():
            entry = self._node_to_entry(node)
            all_params += len(node.parameters)
            all_forms += len(node.forms)

            # Classify into buckets
            if node.has_auth or AUTH_PATTERNS.search(node.path):
                surface.authentication.append(entry)
            elif node.has_upload:
                surface.file_upload.append(entry)
            elif ADMIN_PATTERNS.search(node.path):
                surface.admin_panels.append(entry)
            elif API_PATTERNS.search(node.path):
                surface.api_endpoints.append(entry)
            elif node.has_search:
                surface.search_inputs.append(entry)
            elif STATIC_PATTERNS.search(node.path):
                surface.static_files.append(entry)
            else:
                surface.data_endpoints.append(entry)

            # Check for redirect-vulnerable params
            for p in node.parameters:
                pname = p.get("name", "").lower()
                if pname in REDIRECT_PARAM_NAMES:
                    surface.redirect_params.append({
                        "path": node.path,
                        "url": node.url,
                        "parameter": p.get("name"),
                        "method": node.method,
                    })

            # Collect forms
            for form in node.forms:
                surface.forms.append({
                    "page": node.path,
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET"),
                    "fields": form.get("fields", []),
                    "has_file_upload": form.get("has_file_upload", False),
                    "has_password": form.get("has_password", False),
                })

        surface.total_params = all_params
        surface.total_forms = all_forms
        surface.total_endpoints = len(self._nodes)

        logger.info(
            "[SITEGRAPH] Attack surface mapped: %d endpoints, %d params, %d forms "
            "(%d auth, %d upload, %d api, %d search, %d admin)",
            surface.total_endpoints, all_params, all_forms,
            len(surface.authentication), len(surface.file_upload),
            len(surface.api_endpoints), len(surface.search_inputs),
            len(surface.admin_panels),
        )

        return surface

    # ── Query helpers ─────────────────────────────────────────────────────

    def get_entry_points(self) -> List[SiteNode]:
        """Return high-value nodes worth testing (non-static, with params or forms)."""
        return [
            n for n in self._nodes.values()
            if n.node_type != "static"
            and (n.parameters or n.forms or n.has_auth or n.has_upload)
        ]

    def get_nodes_by_type(self, node_type: str) -> List[SiteNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def get_children(self, path: str) -> List[SiteNode]:
        """Get all nodes reachable from *path* via edges."""
        child_paths = {e.target_path for e in self._edges if e.source_path == path}
        return [self._nodes[f"GET:{p}"] for p in child_paths if f"GET:{p}" in self._nodes]

    def get_tech_hints(self) -> Dict[str, str]:
        """Return SSTI / payload hints based on detected technologies."""
        hints: Dict[str, str] = {}
        for tech in self._technologies:
            if tech in TECH_PAYLOAD_HINTS:
                hints.update(TECH_PAYLOAD_HINTS[tech])
        return hints

    @property
    def technologies(self) -> List[str]:
        return sorted(self._technologies)

    @property
    def nodes(self) -> List[SiteNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[SiteEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ── Serialisation ─────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serializable representation for frontend / reports."""
        return {
            "target": self.target_url,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "technologies": self.technologies,
            "nodes": [
                {
                    "id": n.id,
                    "path": n.path,
                    "method": n.method,
                    "type": n.node_type,
                    "status": n.status_code,
                    "params": n.param_names,
                    "has_auth": n.has_auth,
                    "has_upload": n.has_upload,
                    "depth": n.depth,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_path,
                    "target": e.target_path,
                    "type": e.link_type,
                    "label": e.label,
                }
                for e in self._edges
            ],
        }

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _classify_node(path: str, params: List[Dict], forms: List[Dict]) -> str:
        if STATIC_PATTERNS.search(path):
            return "static"
        if AUTH_PATTERNS.search(path):
            return "auth"
        if ADMIN_PATTERNS.search(path):
            return "admin"
        if UPLOAD_PATTERNS.search(path) or any(f.get("has_file_upload") for f in forms):
            return "upload"
        if API_PATTERNS.search(path):
            return "api"
        if SEARCH_PATTERNS.search(path):
            return "search"
        if forms:
            return "form"
        return "page"

    @staticmethod
    def _node_to_entry(node: SiteNode) -> Dict[str, Any]:
        return {
            "path": node.path,
            "url": node.url,
            "method": node.method,
            "node_type": node.node_type,
            "parameters": [
                f"{node.method} {p.get('name', '?')}" for p in node.parameters
            ],
            "form_count": len(node.forms),
            "technologies": node.technologies,
            "status_code": node.status_code,
            "depth": node.depth,
        }


# ── Robots.txt & Sitemap parser ──────────────────────────────────────────────

class RobotsSitemapParser:
    """
    Parses robots.txt for Disallow / Allow paths and extracts sitemap URLs.
    Parses sitemap.xml for additional endpoint URLs.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")

    async def parse_robots(self, engine) -> Dict[str, Any]:
        """Fetch and parse robots.txt."""
        result = {"disallowed": [], "allowed": [], "sitemaps": []}
        robots_url = f"{self.target_url}/robots.txt"

        resp = await engine.get(robots_url)
        if resp.error or resp.status_code != 200:
            return result

        for line in resp.body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["disallowed"].append(path)
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["allowed"].append(path)
            elif line.lower().startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                # Handle "sitemap: https://..." where split on first ":" removes scheme
                if not url.startswith("http"):
                    url = "https:" + url if "://" not in line else line.split("Sitemap:", 1)[1].strip()
                    if line.lower().startswith("sitemap:"):
                        url = line[len("sitemap:"):].strip()
                        if line[0] == "S":
                            url = line[len("Sitemap:"):].strip()
                result["sitemaps"].append(url)

        logger.info(
            "[SITEGRAPH] robots.txt: %d disallowed, %d allowed, %d sitemaps",
            len(result["disallowed"]), len(result["allowed"]), len(result["sitemaps"]),
        )
        return result

    async def parse_sitemap(self, engine, sitemap_url: Optional[str] = None) -> List[str]:
        """Fetch and parse sitemap.xml for URLs."""
        urls: List[str] = []
        sitemap_url = sitemap_url or f"{self.target_url}/sitemap.xml"

        resp = await engine.get(sitemap_url)
        if resp.error or resp.status_code != 200:
            return urls

        # Extract URLs from <loc> tags
        loc_pattern = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I)
        for match in loc_pattern.finditer(resp.body):
            url = match.group(1).strip()
            if url:
                urls.append(url)

        # Check for sitemap index (nested sitemaps)
        if "<sitemapindex" in resp.body.lower():
            for nested_url in urls[:10]:  # limit nested sitemaps
                nested_urls = await self.parse_sitemap(engine, nested_url)
                urls.extend(nested_urls)

        logger.info("[SITEGRAPH] sitemap parsed: %d URLs from %s", len(urls), sitemap_url)
        return urls


# ── Technology Fingerprinter (Enhanced) ──────────────────────────────────────

class TechFingerprinter:
    """
    Enhanced technology fingerprinting.

    Checks:
    - HTTP headers (Server, X-Powered-By, X-Generator, etc.)
    - HTML meta tags
    - Cookie names
    - Known JavaScript library paths
    - Response body patterns
    """

    HEADER_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
        "server": [
            ("nginx", re.compile(r"nginx", re.I)),
            ("apache", re.compile(r"apache", re.I)),
            ("iis", re.compile(r"microsoft-iis", re.I)),
            ("cloudflare", re.compile(r"cloudflare", re.I)),
            ("litespeed", re.compile(r"litespeed", re.I)),
            ("caddy", re.compile(r"caddy", re.I)),
            ("gunicorn", re.compile(r"gunicorn", re.I)),
        ],
        "x-powered-by": [
            ("php", re.compile(r"php", re.I)),
            ("asp.net", re.compile(r"asp\.net", re.I)),
            ("express", re.compile(r"express", re.I)),
            ("next.js", re.compile(r"next\.js", re.I)),
        ],
    }

    BODY_SIGNATURES: List[Tuple[str, re.Pattern]] = [
        ("wordpress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
        ("drupal", re.compile(r"drupal|sites/default/files", re.I)),
        ("joomla", re.compile(r"joomla|/administrator/", re.I)),
        ("react", re.compile(r"react\.production|_next/static|__NEXT_DATA__", re.I)),
        ("angular", re.compile(r"ng-version|angular\.js|ng-app", re.I)),
        ("vue", re.compile(r"vue\.js|vue\.min\.js|__vue__", re.I)),
        ("jquery", re.compile(r"jquery[.\-/]", re.I)),
        ("bootstrap", re.compile(r"bootstrap[.\-/]", re.I)),
        ("laravel", re.compile(r"laravel|XSRF-TOKEN", re.I)),
        ("django", re.compile(r"csrfmiddlewaretoken|django", re.I)),
        ("flask", re.compile(r"werkzeug|flask", re.I)),
        ("spring", re.compile(r"spring|whitelabel error page", re.I)),
        ("rails", re.compile(r"rails|ruby on rails|csrf-token.*authenticity", re.I)),
        ("graphql", re.compile(r"graphql|__schema", re.I)),
        ("swagger", re.compile(r"swagger|openapi|api-docs", re.I)),
    ]

    COOKIE_SIGNATURES: Dict[str, str] = {
        "PHPSESSID": "php",
        "JSESSIONID": "java",
        "ASP.NET_SessionId": "asp.net",
        "csrftoken": "django",
        "session": "generic",
        "connect.sid": "express",
        "_rails_session": "rails",
        "laravel_session": "laravel",
        "XSRF-TOKEN": "laravel",
    }

    @classmethod
    def fingerprint(
        cls,
        headers: Dict[str, str],
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Return list of detected technologies."""
        detected: Set[str] = set()
        cookies = cookies or {}

        # Header-based detection
        for header_name, patterns in cls.HEADER_SIGNATURES.items():
            value = headers.get(header_name, "")
            for tech, pattern in patterns:
                if pattern.search(value):
                    detected.add(tech)

        # Also check raw header for server version disclosure
        server = headers.get("server", "")
        if server:
            detected.add(f"server:{server.split('/')[0].lower()}")

        # Body-based detection
        for tech, pattern in cls.BODY_SIGNATURES:
            if pattern.search(body):
                detected.add(tech)

        # Cookie-based detection
        all_cookies = {**cookies}
        # Also check Set-Cookie headers
        set_cookie = headers.get("set-cookie", "")
        for cookie_name, tech in cls.COOKIE_SIGNATURES.items():
            if cookie_name in all_cookies or cookie_name.lower() in set_cookie.lower():
                detected.add(tech)

        return sorted(detected)
