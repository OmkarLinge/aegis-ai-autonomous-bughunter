"""
Aegis AI — Strategy Agent (Autonomous Scanner Brain)
Determines scanning strategy, prioritizes endpoints, and reasons about
which attacks to attempt based on discovered context.

This is the "intelligence" layer that makes Aegis act like a real
security researcher rather than a dumb brute-force scanner.
"""
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from agents.endpoint_intelligence_agent import ClassifiedEndpoint
from agents.exploit_agent import VulnerabilityFinding
from utils.logger import get_logger

logger = get_logger(__name__, "STRATEGY")


@dataclass
class ScanStrategy:
    """Represents the scanning strategy for the current target."""
    phase: str
    target_endpoints: List[ClassifiedEndpoint]
    test_sequence: List[Dict]
    reasoning_log: List[str] = field(default_factory=list)
    estimated_duration_seconds: float = 0.0
    risk_level: str = "medium"


@dataclass
class AttackNode:
    """Node in the attack graph."""
    id: str
    label: str
    node_type: str           # target, endpoint_category, vulnerability, impact
    risk: float = 0.0
    discovered: bool = False


@dataclass
class AttackEdge:
    """Edge in the attack graph."""
    source: str
    target: str
    label: str
    attack_type: str          # discovery, exploit, chain
    probability: float = 0.5


class StrategyAgent:
    """
    Strategy Agent — the autonomous brain of the scanner.

    Uses rule-based reasoning (inspired by reinforcement learning concepts)
    to decide:
    1. Which endpoints to scan first
    2. Which vulnerability tests to prioritize
    3. How to chain attack vectors
    4. When to escalate or stop testing

    Reasoning model:
    - High-risk endpoints (admin, auth) → maximum testing depth
    - Medium-risk (API, user data) → standard testing
    - Low-risk (static, info) → basic header checks only
    - Once auth bypass found → expand testing on privileged paths
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.reasoning_log: List[str] = []
        self._findings_context: List[VulnerabilityFinding] = []

    def _reason(self, thought: str):
        """Record a reasoning step (used for LLM reasoning log visualization)."""
        self.reasoning_log.append(thought)
        logger.info(f"[STRATEGY REASONING] {thought}")

    def plan_scan(
        self, classified_endpoints: List[ClassifiedEndpoint]
    ) -> ScanStrategy:
        """
        Create an intelligent scan plan based on discovered endpoints.

        Applies heuristic reasoning to prioritize testing.
        """
        self._reason(f"Analyzing {len(classified_endpoints)} endpoints to create scan strategy")

        # Categorize endpoints
        auth_eps = [e for e in classified_endpoints if e.category == "authentication"]
        admin_eps = [e for e in classified_endpoints if e.category == "admin_panel"]
        upload_eps = [e for e in classified_endpoints if e.category == "file_upload"]
        api_eps = [e for e in classified_endpoints if e.category == "api_endpoint"]
        data_eps = [e for e in classified_endpoints if e.category == "data_retrieval"]
        user_eps = [e for e in classified_endpoints if e.category == "user_data"]

        # Strategic reasoning
        if auth_eps:
            self._reason(
                f"Authentication endpoints detected ({len(auth_eps)} found). "
                "Prioritizing these — successful auth bypass enables access to all protected paths."
            )

        if admin_eps:
            self._reason(
                f"Admin panel detected ({len(admin_eps)} endpoints). "
                "This is highest priority — admin access = full application compromise."
            )

        if upload_eps:
            self._reason(
                f"File upload endpoints detected ({len(upload_eps)} found). "
                "Testing file upload bypass — successful exploit may enable RCE."
            )

        if api_eps:
            self._reason(
                f"{len(api_eps)} API endpoints found. "
                "API endpoints often lack the same input validation as web forms. "
                "Testing injection and IDOR vulnerabilities."
            )

        # Determine overall risk level
        total_high_risk = len(auth_eps) + len(admin_eps) + len(upload_eps)
        if total_high_risk > 5:
            risk_level = "critical"
            self._reason("High concentration of sensitive endpoints — CRITICAL risk profile.")
        elif total_high_risk > 2:
            risk_level = "high"
        elif len(api_eps) > 5:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Build prioritized test sequence
        test_sequence = []
        scan_queue = []

        # Priority 1: Auth endpoints (SQLi for bypass, XSS for session theft)
        for ep in auth_eps:
            scan_queue.append((ep, 1))
            test_sequence.append({
                "endpoint": ep.endpoint.path,
                "tests": ["sql_injection", "xss", "security_headers"],
                "reason": "Authentication endpoint — testing auth bypass payloads",
                "priority": 1,
            })

        # Priority 2: Admin panels
        for ep in admin_eps:
            scan_queue.append((ep, 2))
            test_sequence.append({
                "endpoint": ep.endpoint.path,
                "tests": ["sql_injection", "xss", "auth_bypass"],
                "reason": "Admin panel — testing for unauthorized access",
                "priority": 2,
            })

        # Priority 3: File uploads
        for ep in upload_eps:
            scan_queue.append((ep, 2))
            test_sequence.append({
                "endpoint": ep.endpoint.path,
                "tests": ["file_upload_bypass", "path_traversal"],
                "reason": "File upload — testing for RCE via malicious file upload",
                "priority": 2,
            })

        # Priority 4: API endpoints
        for ep in api_eps[:10]:
            scan_queue.append((ep, 3))
            test_sequence.append({
                "endpoint": ep.endpoint.path,
                "tests": ["sql_injection", "xss", "ssti"],
                "reason": "API endpoint — testing injection vulnerabilities",
                "priority": 3,
            })

        # Priority 5: Data endpoints
        for ep in data_eps[:5] + user_eps[:5]:
            scan_queue.append((ep, 4))
            test_sequence.append({
                "endpoint": ep.endpoint.path,
                "tests": ["sql_injection", "open_redirect"],
                "reason": "Data endpoint — testing for injection and redirect issues",
                "priority": 4,
            })

        # Priority 6: All remaining
        tested_paths = {s["endpoint"] for s in test_sequence}
        for ep in classified_endpoints:
            if ep.endpoint.path not in tested_paths:
                scan_queue.append((ep, 5))

        # Sort by priority
        scan_queue.sort(key=lambda x: x[1])
        prioritized = [ep for ep, _ in scan_queue]

        # Estimate duration (rough: 30s per high-risk endpoint, 10s for others)
        duration = sum(
            30 if ep.risk_score > 0.7 else 10
            for ep in prioritized[:50]
        )

        self._reason(
            f"Scan strategy complete: {len(test_sequence)} targeted tests planned, "
            f"estimated duration ~{duration}s, risk level: {risk_level}"
        )

        return ScanStrategy(
            phase="exploit",
            target_endpoints=prioritized,
            test_sequence=test_sequence,
            reasoning_log=self.reasoning_log.copy(),
            estimated_duration_seconds=duration,
            risk_level=risk_level,
        )

    def adapt_strategy(
        self,
        current_findings: List[VulnerabilityFinding],
        remaining_endpoints: List[ClassifiedEndpoint],
    ) -> List[ClassifiedEndpoint]:
        """
        Adapt scanning strategy based on intermediate findings.
        This simulates the RL-inspired feedback loop.
        """
        self._findings_context = current_findings

        # If we found SQLi, boost priority on data endpoints
        has_sqli = any(f.vuln_type == "sql_injection" for f in current_findings)
        has_auth_bypass = any(
            f.vuln_type in ("sql_injection", "auth_bypass")
            and f.url.endswith(("/login", "/auth", "/signin"))
            for f in current_findings
        )

        if has_sqli:
            self._reason(
                "SQL Injection confirmed — elevating priority of data retrieval endpoints. "
                "Chaining SQLi for deeper data extraction."
            )

        if has_auth_bypass:
            self._reason(
                "Authentication bypass detected — elevating priority of admin/privileged endpoints. "
                "Escalating scan depth on protected paths."
            )
            # Boost admin endpoints to top
            admin_eps = [e for e in remaining_endpoints if e.category == "admin_panel"]
            other_eps = [e for e in remaining_endpoints if e.category != "admin_panel"]
            remaining_endpoints = admin_eps + other_eps

        return remaining_endpoints

    def build_attack_graph(
        self,
        classified: List[ClassifiedEndpoint],
        findings: List[VulnerabilityFinding],
    ) -> Dict:
        """
        Build an attack graph showing discovered vulnerabilities and attack paths.
        """
        nodes = []
        edges = []
        node_ids = set()

        # Root: Target application
        nodes.append({
            "id": "target",
            "label": self.target_url,
            "type": "root",
            "color": "#4f46e5",
        })
        node_ids.add("target")

        # Endpoint category nodes
        categories = {}
        for ep in classified:
            cat = ep.category
            if cat not in categories:
                categories[cat] = {
                    "id": f"cat_{cat}",
                    "label": cat.replace("_", " ").title(),
                    "type": "category",
                    "risk": ep.risk_score,
                    "count": 0,
                    "color": self._category_color(cat),
                }
                node_ids.add(f"cat_{cat}")
            categories[cat]["count"] += 1

        nodes.extend(categories.values())

        # Connect root to categories
        for cat_id in categories:
            edges.append({
                "from": "target",
                "to": f"cat_{cat_id}",
                "label": f"{categories[cat_id]['count']} endpoints",
                "type": "discovery",
            })

        # Vulnerability nodes
        vuln_types_seen = {}
        for finding in findings:
            vtype = finding.vuln_type
            if vtype not in vuln_types_seen:
                vuln_node_id = f"vuln_{vtype}"
                nodes.append({
                    "id": vuln_node_id,
                    "label": finding.title,
                    "type": "vulnerability",
                    "severity": finding.severity,
                    "color": self._severity_color(finding.severity),
                })
                node_ids.add(vuln_node_id)
                vuln_types_seen[vtype] = vuln_node_id

                # Find which category this vuln was found in
                for ep in classified:
                    if ep.endpoint.url == finding.url or ep.endpoint.path in finding.url:
                        edges.append({
                            "from": f"cat_{ep.category}",
                            "to": vuln_node_id,
                            "label": finding.severity,
                            "type": "exploit",
                        })
                        break

        # Add impact nodes for high/critical findings
        for finding in findings:
            if finding.severity in ("HIGH", "CRITICAL"):
                impact_id = f"impact_{finding.vuln_type}"
                if impact_id not in node_ids:
                    nodes.append({
                        "id": impact_id,
                        "label": finding.impact[:40] + "...",
                        "type": "impact",
                        "color": "#ef4444",
                    })
                    node_ids.add(impact_id)
                    edges.append({
                        "from": f"vuln_{finding.vuln_type}",
                        "to": impact_id,
                        "label": "leads to",
                        "type": "impact",
                    })

        return {"nodes": nodes, "edges": edges}

    def _category_color(self, category: str) -> str:
        colors = {
            "authentication": "#f59e0b",
            "admin_panel": "#ef4444",
            "file_upload": "#8b5cf6",
            "api_endpoint": "#3b82f6",
            "data_retrieval": "#10b981",
            "user_data": "#06b6d4",
            "unknown": "#6b7280",
        }
        return colors.get(category, "#6b7280")

    def _severity_color(self, severity: str) -> str:
        colors = {
            "CRITICAL": "#7f1d1d",
            "HIGH": "#ef4444",
            "MEDIUM": "#f59e0b",
            "LOW": "#10b981",
            "INFO": "#6b7280",
        }
        return colors.get(severity, "#6b7280")
