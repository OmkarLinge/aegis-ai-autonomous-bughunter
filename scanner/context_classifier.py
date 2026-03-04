"""
Aegis AI — Payload Context Classifier

Upgrade 3 — Payload Context Engine

Classifies endpoints by their *context* (login, search, upload, redirect,
API, form, admin, static, unknown) and returns the optimal payload set
and parameters to test.

Uses multiple heuristics:
  1. URL path pattern matching
  2. Query-parameter name analysis
  3. HTTP method analysis
  4. Content-type hints
  5. Form field analysis (if available)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "CONTEXT")


# ── Context → payload mapping ───────────────────────────────────────────────

@dataclass
class EndpointContext:
    """Classification result for a single endpoint."""
    category: str                      # login | search | upload | redirect | api | form | admin | static | unknown
    confidence: float                  # 0.0 – 1.0
    recommended_tests: List[str] = field(default_factory=list)
    recommended_params: List[str] = field(default_factory=list)
    reason: str = ""


# Path patterns → (category, confidence)
PATH_RULES: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"/(log[_-]?in|sign[_-]?in|auth|session|oauth)", re.I),  "login", 0.95),
    (re.compile(r"/(register|sign[_-]?up|create[_-]?account)", re.I),     "login", 0.85),
    (re.compile(r"/(search|find|query|lookup|browse)", re.I),              "search", 0.90),
    (re.compile(r"/(upload|attach|file|media|image|document)", re.I),      "upload", 0.90),
    (re.compile(r"/(redirect|goto|return|next|forward|bounce)", re.I),     "redirect", 0.90),
    (re.compile(r"/(admin|dashboard|manage|panel|control)", re.I),         "admin", 0.85),
    (re.compile(r"/(api|graphql|rest|v[0-9]+)/", re.I),                   "api", 0.85),
    (re.compile(r"/(contact|feedback|comment|message|form|submit)", re.I), "form", 0.80),
    (re.compile(r"\.(css|js|png|jpg|gif|svg|woff|ico|map)$", re.I),       "static", 0.99),
    (re.compile(r"/(static|assets|public|dist|build)/", re.I),            "static", 0.95),
]

# Parameter name patterns → category
PARAM_RULES: Dict[str, List[str]] = {
    "login":    ["username", "password", "user", "email", "pass", "login", "credential"],
    "search":   ["q", "query", "search", "keyword", "term", "s", "find"],
    "redirect": ["redirect", "next", "url", "return", "returnTo", "goto", "destination", "target", "continue"],
    "upload":   ["file", "upload", "attachment", "document", "image"],
    "api":      ["api_key", "token", "access_token", "key"],
    "form":     ["name", "email", "message", "subject", "body", "comment", "text"],
}

# Category → recommended tests
CONTEXT_TESTS: Dict[str, List[str]] = {
    "login":    ["sql_injection", "xss", "security_headers"],
    "search":   ["xss", "sql_injection", "ssti", "security_headers"],
    "upload":   ["security_headers"],
    "redirect": ["open_redirect", "security_headers"],
    "admin":    ["sql_injection", "xss", "ssti", "security_headers"],
    "api":      ["sql_injection", "xss", "ssti", "security_headers"],
    "form":     ["xss", "sql_injection", "ssti", "security_headers"],
    "static":   [],  # skip static assets
    "unknown":  ["sql_injection", "xss", "open_redirect", "security_headers"],
}

# Category → recommended parameters to test
CONTEXT_PARAMS: Dict[str, List[str]] = {
    "login":    ["username", "password", "user", "email", "pass"],
    "search":   ["q", "query", "search", "keyword", "term"],
    "upload":   ["file", "upload", "attachment"],
    "redirect": ["redirect", "next", "url", "return", "goto"],
    "admin":    ["username", "password", "token", "role", "id"],
    "api":      ["id", "user_id", "token", "key", "query"],
    "form":     ["name", "email", "message", "subject"],
    "static":   [],
    "unknown":  ["id", "q", "search", "name"],
}


class ContextClassifier:
    """
    Classifies endpoints and selects the optimal payload context.

    Usage:
        classifier = ContextClassifier()
        ctx = classifier.classify(url, params=["q", "page"], method="GET")
        # ctx.category → "search"
        # ctx.recommended_tests → ["xss", "sql_injection", ...]
        # ctx.recommended_params → ["q", "query", ...]
    """

    def classify(
        self,
        url: str,
        params: Optional[List[str]] = None,
        method: str = "GET",
        content_type: str = "",
        form_fields: Optional[List[str]] = None,
    ) -> EndpointContext:
        """Classify an endpoint and return its context."""
        params = params or []
        form_fields = form_fields or []
        all_params = params + form_fields

        best_category = "unknown"
        best_confidence = 0.0
        reason = ""

        # 1) URL path patterns
        path = urlparse(url).path
        for pattern, category, confidence in PATH_RULES:
            if pattern.search(path):
                if confidence > best_confidence:
                    best_category = category
                    best_confidence = confidence
                    reason = f"Path matched: {pattern.pattern}"
                break  # first match wins for path

        # 2) Parameter name analysis (may upgrade confidence)
        param_category, param_conf = self._classify_by_params(all_params)
        if param_conf > best_confidence:
            best_category = param_category
            best_confidence = param_conf
            reason = f"Parameter names matched category '{param_category}'"

        # 3) Method hint
        if method == "POST" and best_category == "unknown":
            best_category = "form"
            best_confidence = max(best_confidence, 0.50)
            reason = reason or "POST method suggests form submission"

        # 4) Content-type hint
        if "multipart" in content_type and best_category != "upload":
            best_category = "upload"
            best_confidence = max(best_confidence, 0.85)
            reason = "multipart/form-data detected"

        # Build result
        return EndpointContext(
            category=best_category,
            confidence=best_confidence,
            recommended_tests=CONTEXT_TESTS.get(best_category, CONTEXT_TESTS["unknown"]),
            recommended_params=CONTEXT_PARAMS.get(best_category, CONTEXT_PARAMS["unknown"]),
            reason=reason,
        )

    def classify_batch(
        self,
        endpoints: List[Dict],
    ) -> List[EndpointContext]:
        """Classify a batch of endpoints."""
        results = []
        for ep in endpoints:
            ctx = self.classify(
                url=ep.get("url", ""),
                params=[p.get("name", "") for p in ep.get("parameters", [])],
                method=ep.get("method", "GET"),
                content_type=ep.get("content_type", ""),
            )
            results.append(ctx)
        return results

    # ── Internal ─────────────────────────────────────────────────────────

    @staticmethod
    def _classify_by_params(params: List[str]) -> Tuple[str, float]:
        """Score parameter names against known category patterns."""
        if not params:
            return "unknown", 0.0

        best_cat = "unknown"
        best_score = 0.0

        param_lower = [p.lower() for p in params]

        for category, keywords in PARAM_RULES.items():
            matches = sum(1 for p in param_lower if p in keywords)
            if matches > 0:
                score = min(0.50 + matches * 0.15, 0.90)
                if score > best_score:
                    best_score = score
                    best_cat = category

        return best_cat, best_score
