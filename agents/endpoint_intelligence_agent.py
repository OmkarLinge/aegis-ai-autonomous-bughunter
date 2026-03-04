"""
Aegis AI — Endpoint Intelligence Agent
Classifies discovered endpoints using NLP patterns and ML techniques.
Assigns risk scores and determines testing priority.
"""
import re
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from scanner.crawler import DiscoveredEndpoint
from utils.config import ENDPOINT_PATTERNS
from utils.logger import get_logger

logger = get_logger(__name__, "ENDPOINT")


@dataclass
class ClassifiedEndpoint:
    """Endpoint with classification metadata and risk assessment."""
    endpoint: DiscoveredEndpoint
    category: str                     # auth, upload, admin, api, etc.
    subcategory: str                  # login, file-upload, rest-api, etc.
    risk_score: float                 # 0.0 - 1.0
    priority: int                     # 1 (highest) - 5 (lowest)
    test_types: List[str]             # Which exploits to attempt
    reasoning: str                    # Agent's reasoning for this classification


# Risk weights for endpoint categories
CATEGORY_RISK = {
    "authentication": 0.9,
    "admin_panel": 0.95,
    "file_upload": 0.85,
    "api_endpoint": 0.7,
    "data_retrieval": 0.65,
    "user_data": 0.6,
    "unknown": 0.3,
}

# Which tests to run per category
CATEGORY_TESTS = {
    "authentication": ["sql_injection", "xss", "brute_force", "security_headers"],
    "admin_panel": ["sql_injection", "xss", "auth_bypass", "security_headers"],
    "file_upload": ["file_upload_bypass", "xss", "path_traversal"],
    "api_endpoint": ["sql_injection", "xss", "open_redirect", "ssti", "security_headers"],
    "data_retrieval": ["sql_injection", "xss", "open_redirect"],
    "user_data": ["sql_injection", "xss", "idor"],
    "unknown": ["security_headers"],
}

# Additional patterns for subcategory detection
SUBCATEGORY_PATTERNS = {
    "login_form": [r"/login", r"/signin", r"/sign-in"],
    "registration": [r"/register", r"/signup", r"/sign-up", r"/create-account"],
    "password_reset": [r"/forgot", r"/reset", r"/recover"],
    "oauth": [r"/oauth", r"/authorize", r"/callback"],
    "rest_api": [r"/api/v\d+", r"/api/"],
    "graphql_api": [r"/graphql", r"/gql"],
    "file_manager": [r"/upload", r"/files", r"/media", r"/documents"],
    "admin_users": [r"/admin/users", r"/admin/accounts"],
    "admin_config": [r"/admin/config", r"/admin/settings"],
    "search": [r"/search", r"\?q=", r"\?query=", r"\?s="],
    "export": [r"/export", r"/download", r"/report"],
}


class EndpointIntelligenceAgent:
    """
    Endpoint Intelligence Agent — classifies and prioritizes endpoints.

    Uses pattern matching and contextual analysis to:
    1. Categorize endpoints by type (auth, API, admin, etc.)
    2. Calculate risk scores based on category and context
    3. Determine which exploit tests to apply
    4. Prioritize testing order for the Strategy Agent
    """

    def __init__(self, on_event: Optional[Callable] = None):
        self.on_event = on_event

    async def _emit(self, message: str, details: dict = None):
        if self.on_event:
            await self.on_event({
                "agent": "ENDPOINT",
                "event_type": "CLASSIFY",
                "message": message,
                "details": details or {},
            })

    async def analyze(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[ClassifiedEndpoint]:
        """
        Analyze and classify all discovered endpoints.

        Returns sorted list of ClassifiedEndpoints by priority.
        """
        logger.info(f"Analyzing {len(endpoints)} endpoints for classification...")
        classified = []

        for endpoint in endpoints:
            classified_ep = self._classify_endpoint(endpoint)
            classified.append(classified_ep)

        # Sort by risk score descending (highest priority first)
        classified.sort(key=lambda x: x.risk_score, reverse=True)

        # Assign priority ranks
        for i, ep in enumerate(classified):
            ep.priority = min(5, (i // (len(classified) // 5 + 1)) + 1)

        # Log summary
        by_category = {}
        for ep in classified:
            by_category[ep.category] = by_category.get(ep.category, 0) + 1

        await self._emit(
            f"Classified {len(classified)} endpoints",
            {"by_category": by_category},
        )

        logger.info(
            f"[ENDPOINT] Classification complete: "
            + ", ".join(f"{k}={v}" for k, v in by_category.items())
        )

        return classified

    def _classify_endpoint(self, endpoint: DiscoveredEndpoint) -> ClassifiedEndpoint:
        """Classify a single endpoint."""
        path = endpoint.path.lower()
        url = endpoint.url.lower()

        # Determine primary category
        category = "unknown"
        category_confidence = 0.0

        for cat, patterns in ENDPOINT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    cat_confidence = 1.0
                    if cat_confidence > category_confidence:
                        category = cat
                        category_confidence = cat_confidence
                    break

        # Determine subcategory
        subcategory = "general"
        for subcat, patterns in SUBCATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, path + url, re.IGNORECASE):
                    subcategory = subcat
                    break

        # Calculate risk score
        base_risk = CATEGORY_RISK.get(category, 0.3)
        risk_modifiers = []
        risk_score = base_risk

        # Boost risk for endpoints with forms
        if endpoint.forms:
            risk_score = min(1.0, risk_score + 0.1)
            risk_modifiers.append("has_forms")

        # Boost risk for endpoints with parameters
        if endpoint.parameters:
            risk_score = min(1.0, risk_score + 0.05)
            risk_modifiers.append("has_parameters")

        # Boost for file upload forms
        if any(f.get("has_file_upload") for f in endpoint.forms):
            risk_score = min(1.0, risk_score + 0.15)
            risk_modifiers.append("file_upload_form")

        # Boost for password forms (authentication)
        if any(f.get("has_password") for f in endpoint.forms):
            risk_score = min(1.0, risk_score + 0.1)
            risk_modifiers.append("password_form")

        # Reduce risk for static resources
        static_exts = [".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff"]
        if any(path.endswith(ext) for ext in static_exts):
            risk_score = 0.1
            risk_modifiers.append("static_resource")

        # Get applicable tests
        test_types = CATEGORY_TESTS.get(category, CATEGORY_TESTS["unknown"]).copy()

        # Add form-specific tests
        if any(f.get("has_file_upload") for f in endpoint.forms):
            if "file_upload_bypass" not in test_types:
                test_types.append("file_upload_bypass")

        # Build reasoning string
        reasoning = (
            f"Classified as '{category}/{subcategory}' "
            f"(risk={risk_score:.2f}) | "
            f"Modifiers: {', '.join(risk_modifiers) or 'none'} | "
            f"Tests: {', '.join(test_types)}"
        )

        logger.debug(f"[ENDPOINT] {endpoint.path} → {category}/{subcategory} risk={risk_score:.2f}")

        return ClassifiedEndpoint(
            endpoint=endpoint,
            category=category,
            subcategory=subcategory,
            risk_score=risk_score,
            priority=3,  # Will be reassigned after sorting
            test_types=test_types,
            reasoning=reasoning,
        )

    def generate_attack_graph(
        self, classified: List[ClassifiedEndpoint]
    ) -> Dict:
        """
        Generate an attack graph showing potential attack paths.

        Returns a graph structure suitable for visualization.
        """
        nodes = []
        edges = []

        # Create nodes for each endpoint category
        category_nodes = {}
        for ep in classified:
            cat = ep.category
            if cat not in category_nodes:
                category_nodes[cat] = {
                    "id": cat,
                    "label": cat.replace("_", " ").title(),
                    "type": "category",
                    "risk": CATEGORY_RISK.get(cat, 0.3),
                    "endpoint_count": 0,
                }
            category_nodes[cat]["endpoint_count"] += 1

        nodes.extend(category_nodes.values())

        # Add target node
        nodes.insert(0, {
            "id": "target",
            "label": "Target Application",
            "type": "target",
            "risk": 0.5,
        })

        # Create attack path edges
        attack_chains = [
            ("authentication", "user_data", "Auth bypass → data access"),
            ("authentication", "admin_panel", "Auth bypass → admin access"),
            ("admin_panel", "data_retrieval", "Admin → database access"),
            ("api_endpoint", "user_data", "API → user data exposure"),
            ("file_upload", "admin_panel", "RCE via upload → full compromise"),
        ]

        for source, target, label in attack_chains:
            if source in category_nodes and target in category_nodes:
                edges.append({
                    "source": source,
                    "target": target,
                    "label": label,
                    "attack_type": "chain",
                })

        # Connect target to all categories
        for cat in category_nodes:
            edges.append({
                "source": "target",
                "target": cat,
                "label": f"discovered {category_nodes[cat]['endpoint_count']} endpoints",
                "attack_type": "discovery",
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "total_endpoints": len(classified),
                "high_risk": sum(1 for e in classified if e.risk_score > 0.7),
                "categories": list(category_nodes.keys()),
            }
        }
