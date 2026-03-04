"""
Aegis AI — Payload Intelligence Engine

Pillar 2 — Context-Aware Payload Generation

Professional scanners do NOT fire random payloads. They:
1. Load payloads from expandable files  (payloads/*.txt)
2. Select payloads based on detected technology (Flask → Jinja SSTI)
3. Choose context-appropriate payloads (search field → XSS, login → SQLi)
4. Apply WAF evasion encodings when needed
5. Mutate payloads with encoding variants (URL, HTML, Unicode)

Usage:
    intel = PayloadIntelligence()
    payloads = intel.get_payloads(
        vuln_type="sql_injection",
        context="login",
        technologies=["php", "mysql"],
        evasion_level=1,
    )
"""
from __future__ import annotations

import html
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "PAYLOAD-INTEL")


# ── Payload file directory ───────────────────────────────────────────────────
PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"


# ── Context → vuln type priority mapping ─────────────────────────────────────
# Which vulnerability types are most relevant for each endpoint context
CONTEXT_PRIORITIES: Dict[str, List[str]] = {
    "login":     ["sql_injection", "xss", "command_injection"],
    "search":    ["xss", "sql_injection", "ssti", "command_injection"],
    "upload":    ["path_traversal", "command_injection"],
    "redirect":  ["open_redirect"],
    "api":       ["sql_injection", "xss", "ssti", "command_injection"],
    "form":      ["xss", "sql_injection", "ssti", "command_injection"],
    "admin":     ["sql_injection", "xss", "command_injection", "ssti"],
    "data":      ["sql_injection", "path_traversal", "xss"],
    "unknown":   ["sql_injection", "xss", "open_redirect", "ssti"],
}

# ── Technology → preferred payload subsets ───────────────────────────────────
# When we know the tech stack, prioritize payloads that match
TECH_PAYLOAD_TAGS: Dict[str, Dict[str, List[str]]] = {
    # Database-specific SQLi
    "mysql":       {"sql_injection": ["SLEEP", "information_schema", "@@version"]},
    "postgres":    {"sql_injection": ["pg_sleep", "version()", "pg_catalog"]},
    "mssql":       {"sql_injection": ["WAITFOR", "@@version", "sys."]},
    "sqlite":      {"sql_injection": ["sqlite_version", "LIKE"]},
    "oracle":      {"sql_injection": ["DBMS_PIPE", "ALL_TABLES", "UTL_HTTP"]},
    # Framework-specific SSTI
    "flask":       {"ssti": ["{{", "config", "__class__", "lipsum"]},
    "jinja2":      {"ssti": ["{{", "config", "__class__", "lipsum"]},
    "django":      {"ssti": ["{% debug %}", "settings.SECRET_KEY"]},
    "php":         {"ssti": ["_self.env", "system", "filter"]},
    "express":     {"ssti": ["<%= ", "global.process"]},
    "rails":       {"ssti": ["<%= ", "system(", "IO.popen"]},
    "spring":      {"ssti": ["${T(java", "Runtime"]},
    "java":        {"ssti": ["${T(java", "Runtime", "freemarker"]},
    # Server-specific path traversal
    "nginx":       {"path_traversal": ["/etc/nginx", "/var/log/nginx"]},
    "apache":      {"path_traversal": ["/etc/apache2", "/var/log/apache2"]},
    "iis":         {"path_traversal": ["\\windows\\", "web.config"]},
}


class PayloadIntelligence:
    """
    Context-aware payload loading, selection, and mutation engine.

    Loads payloads from external files and enhances them with:
    - Technology-aware prioritization
    - Context-based selection
    - WAF evasion encoding
    """

    def __init__(self):
        self._cache: Dict[str, List[str]] = {}

    # ── Public API ────────────────────────────────────────────────────────

    def get_payloads(
        self,
        vuln_type: str,
        context: str = "unknown",
        technologies: Optional[List[str]] = None,
        evasion_level: int = 0,
        max_payloads: int = 50,
    ) -> List[str]:
        """
        Get context-aware payloads for a vulnerability type.

        Args:
            vuln_type:      sql_injection | xss | open_redirect | ssti |
                            command_injection | path_traversal
            context:        login | search | upload | redirect | api | form | admin | unknown
            technologies:   ["flask", "mysql", "nginx", ...]
            evasion_level:  0 = none, 1 = basic encoding, 2 = aggressive evasion
            max_payloads:   maximum number of payloads to return

        Returns:
            Prioritized list of payload strings
        """
        technologies = technologies or []

        # 1. Load base payloads from file
        base_payloads = self._load_payloads(vuln_type)
        if not base_payloads:
            logger.warning("[PAYLOAD-INTEL] No payloads found for %s", vuln_type)
            return []

        # 2. Prioritize by technology
        payloads = self._prioritize_by_tech(base_payloads, vuln_type, technologies)

        # 3. Prioritize by context (move most relevant to front)
        payloads = self._prioritize_by_context(payloads, vuln_type, context)

        # 4. Apply WAF evasion if requested
        if evasion_level > 0:
            payloads = self._apply_evasion(payloads, vuln_type, evasion_level)

        # 5. Truncate
        payloads = payloads[:max_payloads]

        logger.info(
            "[PAYLOAD-INTEL] %s payloads: %d selected (context=%s, techs=%s, evasion=%d)",
            vuln_type, len(payloads), context, technologies[:3], evasion_level,
        )

        return payloads

    def get_context_test_types(self, context: str) -> List[str]:
        """Get the recommended vuln types to test for a given context."""
        return CONTEXT_PRIORITIES.get(context, CONTEXT_PRIORITIES["unknown"])

    def get_available_types(self) -> List[str]:
        """List all available payload types (by file)."""
        types = []
        if PAYLOAD_DIR.is_dir():
            for f in PAYLOAD_DIR.glob("*.txt"):
                types.append(f.stem)
        return sorted(types)

    def get_payload_count(self, vuln_type: str) -> int:
        """Count available payloads for a type."""
        return len(self._load_payloads(vuln_type))

    def get_stats(self) -> Dict[str, Any]:
        """Get payload library statistics."""
        stats = {}
        for vtype in self.get_available_types():
            payloads = self._load_payloads(vtype)
            stats[vtype] = len(payloads)
        stats["total"] = sum(stats.values())
        return stats

    # ── Payload loading ───────────────────────────────────────────────────

    def _load_payloads(self, vuln_type: str) -> List[str]:
        """Load payloads from file with caching."""
        if vuln_type in self._cache:
            return self._cache[vuln_type]

        # Map vuln_type to filename
        file_map = {
            "sql_injection": "sqli",
            "xss": "xss",
            "open_redirect": "redirect",
            "ssti": "ssti",
            "command_injection": "command_injection",
            "path_traversal": "path_traversal",
        }
        filename = file_map.get(vuln_type, vuln_type)
        filepath = PAYLOAD_DIR / f"{filename}.txt"

        if not filepath.is_file():
            logger.debug("[PAYLOAD-INTEL] No payload file: %s", filepath)
            self._cache[vuln_type] = []
            return []

        payloads = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue
                payloads.append(line)

        self._cache[vuln_type] = payloads
        return payloads

    # ── Technology prioritization ─────────────────────────────────────────

    def _prioritize_by_tech(
        self,
        payloads: List[str],
        vuln_type: str,
        technologies: List[str],
    ) -> List[str]:
        """Move tech-specific payloads to the front."""
        if not technologies:
            return payloads

        # Gather keywords for this vuln_type from matching technologies
        keywords: List[str] = []
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECH_PAYLOAD_TAGS:
                tags = TECH_PAYLOAD_TAGS[tech_lower].get(vuln_type, [])
                keywords.extend(tags)

        if not keywords:
            return payloads

        # Split into tech-relevant and general
        tech_relevant: List[str] = []
        general: List[str] = []
        for p in payloads:
            if any(kw.lower() in p.lower() for kw in keywords):
                tech_relevant.append(p)
            else:
                general.append(p)

        return tech_relevant + general

    # ── Context prioritization ────────────────────────────────────────────

    def _prioritize_by_context(
        self,
        payloads: List[str],
        vuln_type: str,
        context: str,
    ) -> List[str]:
        """Reorder payloads based on endpoint context."""
        # Context-specific payload keywords to prioritize
        context_keywords: Dict[str, Dict[str, List[str]]] = {
            "login": {
                "sql_injection": ["OR '1'='1", "admin", "bypass", "OR 1=1"],
                "xss": ["onfocus", "autofocus", "onerror"],
            },
            "search": {
                "xss": ["script", "alert", "onerror", "svg"],
                "sql_injection": ["UNION", "SELECT", "OR"],
            },
            "api": {
                "sql_injection": ["{", "json", "id"],
                "xss": ["${", "constructor"],
            },
            "form": {
                "xss": ["onfocus", "autofocus", "attribute", "onmouseover"],
                "ssti": ["{{", "${", "<%"],
            },
        }

        keywords = context_keywords.get(context, {}).get(vuln_type, [])
        if not keywords:
            return payloads

        prioritized: List[str] = []
        rest: List[str] = []
        for p in payloads:
            if any(kw.lower() in p.lower() for kw in keywords):
                prioritized.append(p)
            else:
                rest.append(p)

        return prioritized + rest

    # ── WAF evasion ───────────────────────────────────────────────────────

    def _apply_evasion(
        self,
        payloads: List[str],
        vuln_type: str,
        level: int,
    ) -> List[str]:
        """
        Add WAF evasion variants to the payload list.

        Level 1: URL encoding
        Level 2: URL + HTML + case mutation + Unicode
        """
        result = list(payloads)  # start with originals

        for p in payloads[:20]:  # only mutate first 20 to avoid payload explosion
            if level >= 1:
                # URL encoding
                encoded = quote(p, safe="")
                if encoded != p:
                    result.append(encoded)

                # Double URL encoding
                double = quote(encoded, safe="")
                if double != encoded:
                    result.append(double)

            if level >= 2:
                # HTML entity encoding (for XSS)
                if vuln_type == "xss":
                    result.append(html.escape(p))

                # Case randomization (for SQLi / XSS)
                if vuln_type in ("sql_injection", "xss"):
                    result.append(self._randomize_case(p))

                # Tab/newline insertion
                result.append(p.replace(" ", "%09"))
                result.append(p.replace(" ", "%0a"))

        # Deduplicate while preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for p in result:
            if p not in seen:
                seen.add(p)
                deduped.append(p)

        return deduped

    @staticmethod
    def _randomize_case(s: str) -> str:
        """Alternate case for WAF evasion."""
        result = []
        for i, c in enumerate(s):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return "".join(result)
