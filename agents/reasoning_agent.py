"""
Aegis AI — AI Reasoning Agent

Pillar 7 — Agentic Testing Intelligence

This agent makes *intelligent decisions* about WHAT to test and HOW,
based on accumulated knowledge from earlier pipeline stages.

Instead of blindly testing every payload on every endpoint, the
Reasoning Agent:

1. Analyses the attack surface map → decides which endpoints deserve
   deeper testing
2. Inspects response context → decides which XSS context (attribute,
   script, href) to target
3. Adapts to WAF detection → enables evasion payloads
4. Chains findings → if SQLi confirmed on /api, test /admin with same
   approach
5. Produces reasoning log so humans can understand WHY each decision
   was made

This is what makes Aegis *agentic* — it doesn't just scan, it THINKS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "REASONING")


# ── Decision types ────────────────────────────────────────────────────────────

@dataclass
class TestDecision:
    """A decision about what to test on a specific endpoint."""
    endpoint_path: str
    endpoint_url: str
    test_types: List[str]                # vuln types to test
    priority_params: List[str]           # params to test first
    evasion_level: int = 0               # 0 = none, 1 = basic, 2 = aggressive
    context_hints: Dict[str, str] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)
    skip: bool = False                   # True if agent decides to skip
    skip_reason: str = ""


@dataclass
class ReasoningReport:
    """Summary of all reasoning decisions made during a scan."""
    decisions: List[TestDecision]
    waf_detected: bool = False
    waf_type: str = ""
    tech_stack: List[str] = field(default_factory=list)
    high_value_targets: List[str] = field(default_factory=list)
    reasoning_log: List[str] = field(default_factory=list)
    total_endpoints: int = 0
    endpoints_to_test: int = 0
    endpoints_skipped: int = 0


# ── WAF detection signatures ────────────────────────────────────────────────

WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": [
        "cf-ray", "cf-cache-status", "__cfduid", "cloudflare",
        "attention required! | cloudflare",
    ],
    "aws_waf": [
        "x-amzn-requestid", "x-amz-cf-id", "awselb", "aws",
    ],
    "akamai": [
        "akamai", "x-akamai", "akamaighost",
    ],
    "imperva": [
        "x-iinfo", "incapsula", "imperva", "visid_incap",
    ],
    "modsecurity": [
        "mod_security", "modsecurity", "not acceptable",
    ],
    "sucuri": [
        "x-sucuri", "sucuri", "cloudproxy",
    ],
    "f5_bigip": [
        "bigipserver", "f5", "x-wa-info",
    ],
}

# ── Response context patterns for XSS ────────────────────────────────────────

XSS_CONTEXTS: Dict[str, re.Pattern] = {
    "html_tag":      re.compile(r"<[a-z]+[^>]*>[^<]*REFLECTION", re.I),
    "html_attr":     re.compile(r'<[a-z]+[^>]*(?:value|href|src|action)=["\']?[^"\']*REFLECTION', re.I),
    "script_block":  re.compile(r"<script[^>]*>[^<]*REFLECTION", re.I),
    "js_string":     re.compile(r"""(?:var|let|const|=)\s*['"][^'"]*REFLECTION""", re.I),
    "url_context":   re.compile(r"(?:href|src|action|url)\s*=\s*['\"]?[^'\"]*REFLECTION", re.I),
    "comment":       re.compile(r"<!--[^>]*REFLECTION", re.I),
    "css_context":   re.compile(r"<style[^>]*>[^<]*REFLECTION", re.I),
}


class ReasoningAgent:
    """
    AI Reasoning Agent — makes intelligent decisions about vulnerability testing.

    This agent operates between the Strategy Agent and the Exploit Agent:
    1. Receives classified endpoints + attack surface
    2. Analyses WAF, technology, response context
    3. Produces TestDecisions for each endpoint
    4. The Exploit Agent follows these decisions
    """

    def __init__(self, on_event=None):
        self.on_event = on_event
        self._reasoning_log: List[str] = []
        self._waf_detected = False
        self._waf_type = ""
        self._confirmed_vulns: Dict[str, List[str]] = {}  # vuln_type → [urls]

    async def _emit(self, message: str, details: Optional[dict] = None):
        if self.on_event:
            await self.on_event({
                "agent": "REASONING",
                "event_type": "DECISION",
                "message": message,
                "details": details or {},
            })

    def _reason(self, thought: str):
        self._reasoning_log.append(thought)
        logger.info("[REASONING] %s", thought)

    # ── Main entry point ──────────────────────────────────────────────────

    async def analyze(
        self,
        classified_endpoints: List[Any],
        attack_surface: Any,
        technologies: List[str],
        baseline_headers: Optional[Dict[str, str]] = None,
    ) -> ReasoningReport:
        """
        Analyze the target and produce intelligent testing decisions.

        Args:
            classified_endpoints: List of ClassifiedEndpoint from intel agent
            attack_surface: AttackSurface from SiteGraph
            technologies: Detected technologies
            baseline_headers: Headers from initial request (for WAF detection)

        Returns:
            ReasoningReport with decisions for each endpoint
        """
        self._reason("Beginning intelligent analysis of target application")
        baseline_headers = baseline_headers or {}

        # ── Step 1: WAF Detection ────────────────────────────────────────
        self._detect_waf(baseline_headers)

        # ── Step 2: Technology Analysis ──────────────────────────────────
        tech_analysis = self._analyze_tech_stack(technologies)

        # ── Step 3: Identify High-Value Targets ─────────────────────────
        high_value = self._identify_high_value(classified_endpoints, attack_surface)

        # ── Step 4: Generate Decisions ───────────────────────────────────
        decisions: List[TestDecision] = []
        skipped = 0

        for ep in classified_endpoints:
            decision = self._make_decision(ep, attack_surface, technologies)
            decisions.append(decision)
            if decision.skip:
                skipped += 1

        self._reason(
            f"Analysis complete: {len(decisions)} endpoints analyzed, "
            f"{len(decisions) - skipped} will be tested, {skipped} skipped"
        )

        await self._emit(
            f"Reasoning complete: {len(decisions) - skipped} endpoints selected for testing",
            {"skipped": skipped, "waf": self._waf_type or "none"},
        )

        return ReasoningReport(
            decisions=decisions,
            waf_detected=self._waf_detected,
            waf_type=self._waf_type,
            tech_stack=technologies,
            high_value_targets=high_value,
            reasoning_log=self._reasoning_log,
            total_endpoints=len(classified_endpoints),
            endpoints_to_test=len(decisions) - skipped,
            endpoints_skipped=skipped,
        )

    # ── WAF Detection ─────────────────────────────────────────────────────

    def _detect_waf(self, headers: Dict[str, str]):
        """Detect WAF/CDN from response headers."""
        combined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    self._waf_detected = True
                    self._waf_type = waf_name
                    self._reason(
                        f"WAF DETECTED: {waf_name} — enabling evasion payloads"
                    )
                    return

        self._reason("No WAF detected — standard payloads will be used")

    # ── Technology Analysis ───────────────────────────────────────────────

    def _analyze_tech_stack(self, technologies: List[str]) -> Dict[str, str]:
        """Analyze tech stack and produce payload strategy hints."""
        hints: Dict[str, str] = {}

        tech_lower = {t.lower() for t in technologies}

        # Database detection → SQLi strategy
        if tech_lower & {"mysql", "mariadb"}:
            hints["sqli_strategy"] = "mysql"
            self._reason("MySQL detected → prioritizing MySQL-specific SQLi payloads")
        elif tech_lower & {"postgresql", "postgres"}:
            hints["sqli_strategy"] = "postgres"
            self._reason("PostgreSQL detected → using pg_sleep and PG-specific payloads")
        elif tech_lower & {"mssql", "sql server"}:
            hints["sqli_strategy"] = "mssql"
            self._reason("MSSQL detected → using WAITFOR DELAY and MSSQL payloads")

        # Framework detection → SSTI strategy
        if tech_lower & {"flask", "jinja2"}:
            hints["ssti_engine"] = "jinja2"
            self._reason("Flask/Jinja2 detected → using Jinja2 SSTI payloads")
        elif tech_lower & {"django"}:
            hints["ssti_engine"] = "django"
            self._reason("Django detected → using Django template payloads")
        elif tech_lower & {"php", "laravel"}:
            hints["ssti_engine"] = "twig"
            self._reason("PHP detected → using Twig SSTI payloads")
        elif tech_lower & {"express", "node", "ejs"}:
            hints["ssti_engine"] = "ejs"
            self._reason("Express/Node detected → using EJS SSTI payloads")
        elif tech_lower & {"spring", "java", "thymeleaf"}:
            hints["ssti_engine"] = "thymeleaf"
            self._reason("Spring/Java detected → using Thymeleaf SSTI payloads")

        if not hints:
            self._reason("No specific technology detected — using generic payloads")

        return hints

    # ── High-Value Target Identification ─────────────────────────────────

    def _identify_high_value(
        self,
        endpoints: List[Any],
        attack_surface: Any,
    ) -> List[str]:
        """Identify the most critical endpoints to test."""
        high_value: List[str] = []

        # Auth endpoints are always high-value
        if hasattr(attack_surface, "authentication"):
            for entry in attack_surface.authentication:
                path = entry.get("path", "")
                high_value.append(path)
                self._reason(f"HIGH VALUE: {path} — authentication endpoint")

        # Upload endpoints are high-value
        if hasattr(attack_surface, "file_upload"):
            for entry in attack_surface.file_upload:
                path = entry.get("path", "")
                high_value.append(path)
                self._reason(f"HIGH VALUE: {path} — file upload endpoint")

        # Admin endpoints are high-value
        if hasattr(attack_surface, "admin_panels"):
            for entry in attack_surface.admin_panels:
                path = entry.get("path", "")
                high_value.append(path)
                self._reason(f"HIGH VALUE: {path} — admin panel")

        # API endpoints with parameters
        if hasattr(attack_surface, "api_endpoints"):
            for entry in attack_surface.api_endpoints:
                if entry.get("parameters"):
                    path = entry.get("path", "")
                    high_value.append(path)

        if high_value:
            self._reason(f"Identified {len(high_value)} high-value targets")
        else:
            self._reason("No high-value targets identified — testing all endpoints")

        return high_value

    # ── Decision Making ───────────────────────────────────────────────────

    def _make_decision(
        self,
        classified_endpoint: Any,
        attack_surface: Any,
        technologies: List[str],
    ) -> TestDecision:
        """Make an intelligent testing decision for a single endpoint."""
        ep = classified_endpoint.endpoint
        category = classified_endpoint.category or "unknown"
        risk_score = classified_endpoint.risk_score
        path = ep.path
        url = ep.url
        params = [p.get("name", "") for p in ep.parameters]

        decision = TestDecision(
            endpoint_path=path,
            endpoint_url=url,
            test_types=[],
            priority_params=[],
        )

        # ── Skip static resources ────────────────────────────────────────
        if category == "static" or re.search(
            r"\.(css|js|png|jpg|gif|svg|ico|woff|ttf|eot|pdf)$", path, re.I
        ):
            decision.skip = True
            decision.skip_reason = "Static resource — no injection points"
            return decision

        # ── Skip very low risk ───────────────────────────────────────────
        if risk_score < 0.15 and not params and not ep.forms:
            decision.skip = True
            decision.skip_reason = f"Low risk ({risk_score:.2f}) with no parameters"
            return decision

        # ── Decide test types based on category ─────────────────────────
        test_map = {
            "auth":     ["sql_injection", "xss", "command_injection"],
            "admin":    ["sql_injection", "xss", "command_injection", "ssti"],
            "upload":   ["path_traversal", "command_injection"],
            "api":      ["sql_injection", "xss", "ssti", "command_injection"],
            "search":   ["xss", "sql_injection", "ssti"],
            "form":     ["xss", "sql_injection", "ssti", "command_injection"],
            "data":     ["sql_injection", "path_traversal", "xss"],
            "page":     ["xss", "sql_injection", "open_redirect"],
            "unknown":  ["sql_injection", "xss", "open_redirect"],
        }
        decision.test_types = test_map.get(category, test_map["unknown"])

        # Always add security headers check
        decision.test_types.append("security_headers")

        # ── Decide priority parameters ──────────────────────────────────
        # Parameters that hint at specific vulnerabilities get priority
        sqli_param_hints = {"id", "user", "uid", "user_id", "item", "order", "product"}
        xss_param_hints = {"q", "query", "search", "name", "message", "comment", "text"}
        redirect_param_hints = {"url", "redirect", "next", "return", "goto", "dest"}
        file_param_hints = {"file", "path", "page", "template", "include", "doc", "folder"}

        priority_params: List[str] = []
        for p in params:
            p_lower = p.lower()
            if p_lower in sqli_param_hints:
                priority_params.append(p)
                if "sql_injection" not in decision.test_types:
                    decision.test_types.insert(0, "sql_injection")
                decision.reasoning.append(f"Param '{p}' hints at SQLi")
            elif p_lower in xss_param_hints:
                priority_params.append(p)
                decision.reasoning.append(f"Param '{p}' hints at XSS")
            elif p_lower in redirect_param_hints:
                priority_params.append(p)
                if "open_redirect" not in decision.test_types:
                    decision.test_types.insert(0, "open_redirect")
                decision.reasoning.append(f"Param '{p}' hints at open redirect")
            elif p_lower in file_param_hints:
                priority_params.append(p)
                if "path_traversal" not in decision.test_types:
                    decision.test_types.insert(0, "path_traversal")
                decision.reasoning.append(f"Param '{p}' hints at path traversal")

        # Remaining params go after priority params
        for p in params:
            if p not in priority_params:
                priority_params.append(p)

        decision.priority_params = priority_params

        # ── Set evasion level ────────────────────────────────────────────
        if self._waf_detected:
            decision.evasion_level = 2 if self._waf_type in ("cloudflare", "aws_waf", "imperva") else 1
            decision.reasoning.append(
                f"WAF ({self._waf_type}) detected → evasion level {decision.evasion_level}"
            )

        # ── Context hints based on forms ─────────────────────────────────
        for form in ep.forms:
            if form.get("has_password"):
                decision.context_hints["has_password_field"] = "true"
                decision.reasoning.append("Form has password field → prioritize auth bypass SQLi")
            if form.get("has_file_upload"):
                decision.context_hints["has_file_upload"] = "true"
                if "path_traversal" not in decision.test_types:
                    decision.test_types.insert(0, "path_traversal")
                decision.reasoning.append("Form has file upload → test path traversal")

        decision.reasoning.append(
            f"Decision: test {', '.join(decision.test_types)} on {len(decision.priority_params)} params"
        )

        return decision

    # ── Adaptive learning (mid-scan) ─────────────────────────────────────

    def adapt_from_finding(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        confidence: float,
    ):
        """
        Called when the exploit agent confirms a vulnerability.
        Allows the reasoning agent to adapt strategy for remaining endpoints.
        """
        self._confirmed_vulns.setdefault(vuln_type, []).append(url)

        from urllib.parse import urlparse
        path = urlparse(url).path

        if vuln_type == "sql_injection" and confidence >= 0.7:
            self._reason(
                f"ADAPT: SQLi confirmed on {path} — will prioritize SQLi on "
                f"similar endpoints (same path pattern)"
            )
        elif vuln_type == "xss" and confidence >= 0.7:
            self._reason(
                f"ADAPT: XSS confirmed on {path} — checking if same param "
                f"exists on other endpoints"
            )

    def get_reasoning_log(self) -> List[str]:
        return self._reasoning_log

    # ── XSS Context Analysis ─────────────────────────────────────────────

    @staticmethod
    def analyze_xss_context(
        response_body: str,
        reflection_marker: str = "AEGIS_CANARY_12345",
    ) -> Dict[str, Any]:
        """
        Analyse where a reflection lands in the HTML to choose the right
        XSS payload context.

        Returns dict with:
          context: html_tag | html_attr | script_block | js_string | url_context
          recommended_payloads: list of payload suggestions
        """
        result: Dict[str, Any] = {
            "context": "unknown",
            "contexts_found": [],
            "recommended_payloads": [],
        }

        for ctx_name, pattern in XSS_CONTEXTS.items():
            adjusted = pattern.pattern.replace("REFLECTION", re.escape(reflection_marker))
            if re.search(adjusted, response_body, re.I):
                result["contexts_found"].append(ctx_name)

        if not result["contexts_found"]:
            result["context"] = "unknown"
            result["recommended_payloads"] = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
            ]
            return result

        # Pick the most exploitable context
        ctx = result["contexts_found"][0]
        result["context"] = ctx

        payload_map = {
            "html_tag": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "html_attr": [
                '"><script>alert(1)</script>',
                '" onfocus="alert(1)" autofocus="',
                "' onmouseover='alert(1)",
            ],
            "script_block": [
                "</script><script>alert(1)</script>",
                "';alert(1);//",
                "\";alert(1);//",
            ],
            "js_string": [
                "';alert(1);//",
                "\";alert(1);//",
                "'-alert(1)-'",
            ],
            "url_context": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
            "comment": [
                "--><script>alert(1)</script><!--",
            ],
            "css_context": [
                "}</style><script>alert(1)</script>",
            ],
        }

        result["recommended_payloads"] = payload_map.get(ctx, [
            "<script>alert(1)</script>"
        ])

        return result
