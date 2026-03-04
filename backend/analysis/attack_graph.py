"""
Aegis AI — Attack Graph Engine
Builds a directed graph of attack paths using NetworkX.

Nodes represent:
  - endpoints   (discovered URLs / routes)
  - vulnerabilities   (confirmed or suspected findings)
  - impacts     (consequences: DB access, admin takeover, etc.)

Edges represent how an attacker can move from one state to the next.

The engine computes:
  • All simple attack paths from an entry-point to every impact node
  • Per-path risk scores (product of edge probabilities × node severity)
  • Global risk metrics aggregated across every path
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import networkx as nx

# ── Severity → numeric CVSS-style score ──────────────────────────────────────

SEVERITY_SCORE: Dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 1.0,
}

# ── Vulnerability → likely impact mapping ────────────────────────────────────

VULN_IMPACT_MAP: Dict[str, List[Dict]] = {
    "sql_injection": [
        {"id": "impact_db_access", "label": "Database Compromise", "severity": 9.0,
         "description": "Full read/write access to backend database"},
        {"id": "impact_data_exfil", "label": "Data Exfiltration", "severity": 8.5,
         "description": "Extraction of sensitive user/business data"},
    ],
    "xss": [
        {"id": "impact_session_hijack", "label": "Session Hijacking", "severity": 7.0,
         "description": "Steal user session cookies via injected script"},
        {"id": "impact_phishing", "label": "Phishing / Credential Theft", "severity": 6.5,
         "description": "Present fake login forms to harvest credentials"},
    ],
    "open_redirect": [
        {"id": "impact_phishing", "label": "Phishing / Credential Theft", "severity": 6.5,
         "description": "Redirect users to attacker-controlled site"},
    ],
    "ssti": [
        {"id": "impact_rce", "label": "Remote Code Execution", "severity": 10.0,
         "description": "Execute arbitrary code on the server"},
    ],
    "auth_bypass": [
        {"id": "impact_admin_access", "label": "Admin Access", "severity": 9.0,
         "description": "Full administrative access to the application"},
    ],
    "file_upload_bypass": [
        {"id": "impact_rce", "label": "Remote Code Execution", "severity": 10.0,
         "description": "Execute arbitrary code via uploaded webshell"},
    ],
    "path_traversal": [
        {"id": "impact_data_exfil", "label": "Data Exfiltration", "severity": 8.5,
         "description": "Read arbitrary files from the server"},
    ],
    "missing_security_header": [
        {"id": "impact_increased_surface", "label": "Increased Attack Surface", "severity": 3.0,
         "description": "Missing headers widen the attack surface for other exploits"},
    ],
    "server_version_disclosure": [
        {"id": "impact_recon_aid", "label": "Reconnaissance Aid", "severity": 2.0,
         "description": "Version info helps attackers find known CVEs"},
    ],
    "idor": [
        {"id": "impact_data_exfil", "label": "Data Exfiltration", "severity": 8.0,
         "description": "Access other users' data via insecure direct object references"},
    ],
}

# Probability that exploiting a vuln leads to the mapped impact
VULN_PROBABILITY: Dict[str, float] = {
    "sql_injection": 0.85,
    "xss": 0.70,
    "open_redirect": 0.60,
    "ssti": 0.90,
    "auth_bypass": 0.90,
    "file_upload_bypass": 0.80,
    "path_traversal": 0.75,
    "missing_security_header": 0.30,
    "server_version_disclosure": 0.20,
    "idor": 0.80,
}


@dataclass
class AttackPath:
    """A single path through the attack graph."""
    nodes: List[str]
    labels: List[str]
    risk_score: float
    description: str


class AttackGraph:
    """
    Directed graph representing all discovered attack paths.

    Usage:
        ag = AttackGraph(target_url="https://target.com")
        ag.add_endpoint("/login", category="authentication", risk=0.9)
        ag.add_vulnerability("sql_injection", severity="HIGH", ...)
        ag.link_vulnerability("/login", "sql_injection")
        ag.add_impacts()             # auto-adds consequence nodes
        ag.compute_all_paths()       # finds every path → impact
    """

    def __init__(self, target_url: str = ""):
        self.graph = nx.DiGraph()
        self.target_url = target_url
        self._paths: List[AttackPath] = []

        # Add attacker entry-point node
        self.graph.add_node(
            "attacker",
            label="Attacker",
            node_type="attacker",
            risk=0.0,
            color="#6366f1",
        )

    # ── Node helpers ─────────────────────────────────────────────────────

    def add_endpoint(
        self,
        endpoint_id: str,
        *,
        label: str | None = None,
        category: str = "unknown",
        risk: float = 0.5,
        color: str | None = None,
    ):
        """Add an endpoint node (e.g. /login, /api/user)."""
        color = color or _category_color(category)
        self.graph.add_node(
            endpoint_id,
            label=label or endpoint_id,
            node_type="endpoint",
            category=category,
            risk=risk,
            color=color,
        )
        # Connect attacker → endpoint (discovery edge)
        self.graph.add_edge(
            "attacker", endpoint_id,
            label="discovers",
            edge_type="discovery",
            probability=1.0,
        )

    def add_vulnerability(
        self,
        vuln_id: str,
        *,
        label: str = "",
        vuln_type: str = "",
        severity: str = "MEDIUM",
        confidence: float = 0.5,
        color: str | None = None,
    ):
        """Add a vulnerability node."""
        score = SEVERITY_SCORE.get(severity, 5.0)
        color = color or _severity_color(severity)
        self.graph.add_node(
            vuln_id,
            label=label or vuln_type.replace("_", " ").title(),
            node_type="vulnerability",
            vuln_type=vuln_type,
            severity=severity,
            risk=score,
            confidence=confidence,
            color=color,
        )

    def link_vulnerability(
        self,
        endpoint_id: str,
        vuln_id: str,
        *,
        label: str = "exploits",
        probability: float = 0.7,
    ):
        """Create edge: endpoint → vulnerability."""
        self.graph.add_edge(
            endpoint_id, vuln_id,
            label=label,
            edge_type="exploit",
            probability=probability,
        )

    def add_impact(
        self,
        impact_id: str,
        *,
        label: str = "",
        severity: float = 8.0,
        description: str = "",
        color: str = "#ef4444",
    ):
        """Add an impact / consequence node."""
        if not self.graph.has_node(impact_id):
            self.graph.add_node(
                impact_id,
                label=label,
                node_type="impact",
                risk=severity,
                description=description,
                color=color,
            )

    def link_impact(
        self,
        vuln_id: str,
        impact_id: str,
        *,
        label: str = "leads to",
        probability: float = 0.8,
    ):
        """Create edge: vulnerability → impact."""
        self.graph.add_edge(
            vuln_id, impact_id,
            label=label,
            edge_type="impact",
            probability=probability,
        )

    # ── Bulk builders ────────────────────────────────────────────────────

    def add_impacts_for_vulnerabilities(self):
        """
        Automatically attach impact nodes to every vulnerability node
        based on the VULN_IMPACT_MAP lookup table.
        """
        vuln_nodes = [
            (nid, data)
            for nid, data in self.graph.nodes(data=True)
            if data.get("node_type") == "vulnerability"
        ]
        for vuln_id, data in vuln_nodes:
            vtype = data.get("vuln_type", "")
            impacts = VULN_IMPACT_MAP.get(vtype, [])
            prob = VULN_PROBABILITY.get(vtype, 0.5)
            for imp in impacts:
                self.add_impact(
                    imp["id"],
                    label=imp["label"],
                    severity=imp["severity"],
                    description=imp.get("description", ""),
                )
                self.link_impact(vuln_id, imp["id"], probability=prob)

    def build_from_scan_results(
        self,
        endpoints: List[Dict],
        vulnerabilities: List[Dict],
    ):
        """
        Populate graph from raw orchestrator scan state dicts.

        Args:
            endpoints: list of endpoint dicts (from scan state)
            vulnerabilities: list of vulnerability dicts (from scan state)
        """
        # Group endpoints by category
        categories_seen: Dict[str, List[Dict]] = {}
        for ep in endpoints:
            cat = ep.get("endpoint_type", "unknown")
            categories_seen.setdefault(cat, []).append(ep)

        # Add category-level endpoint nodes
        for cat, eps in categories_seen.items():
            cat_id = f"cat_{cat}"
            self.add_endpoint(
                cat_id,
                label=f"{cat.replace('_', ' ').title()} ({len(eps)})",
                category=cat,
                risk=max(e.get("risk_score", 0.3) for e in eps),
            )

        # Add individual high-risk endpoints
        for ep in endpoints:
            risk = ep.get("risk_score", 0.3)
            if risk >= 0.6:
                ep_id = f"ep_{ep['path']}"
                cat = ep.get("endpoint_type", "unknown")
                self.add_endpoint(
                    ep_id,
                    label=ep["path"],
                    category=cat,
                    risk=risk,
                )
                # Connect category → specific endpoint
                cat_id = f"cat_{cat}"
                if self.graph.has_node(cat_id):
                    self.graph.add_edge(
                        cat_id, ep_id,
                        label="includes",
                        edge_type="contains",
                        probability=1.0,
                    )

        # Add vulnerability nodes & edges
        for i, vuln in enumerate(vulnerabilities):
            vtype = vuln.get("vuln_type", "unknown")
            vuln_id = f"vuln_{vtype}_{i}"
            self.add_vulnerability(
                vuln_id,
                label=vuln.get("title", vtype),
                vuln_type=vtype,
                severity=vuln.get("severity", "MEDIUM"),
                confidence=vuln.get("confidence", 0.5),
            )

            # Link to matching endpoint
            vuln_url = vuln.get("url", "")
            linked = False
            for ep in endpoints:
                if ep["path"] in vuln_url or vuln_url.endswith(ep["path"]):
                    ep_id = f"ep_{ep['path']}"
                    if self.graph.has_node(ep_id):
                        self.link_vulnerability(ep_id, vuln_id)
                        linked = True
                        break

            # Fallback: link to category node
            if not linked:
                for ep in endpoints:
                    if ep["path"] in vuln_url or vuln_url.endswith(ep["path"]):
                        cat_id = f"cat_{ep.get('endpoint_type', 'unknown')}"
                        if self.graph.has_node(cat_id):
                            self.link_vulnerability(cat_id, vuln_id)
                            linked = True
                            break

            # Last resort: link to first category
            if not linked and categories_seen:
                first_cat = f"cat_{next(iter(categories_seen))}"
                if self.graph.has_node(first_cat):
                    self.link_vulnerability(first_cat, vuln_id)

        # Auto-add impact nodes
        self.add_impacts_for_vulnerabilities()

    # ── Path & risk computation ──────────────────────────────────────────

    def compute_all_paths(self, max_paths: int = 200) -> List[AttackPath]:
        """
        Find all simple paths from 'attacker' to every impact node.
        Score each path by multiplying edge probabilities × node severity.
        """
        impact_nodes = [
            nid for nid, d in self.graph.nodes(data=True)
            if d.get("node_type") == "impact"
        ]
        paths: List[AttackPath] = []

        for impact_id in impact_nodes:
            try:
                raw_paths = list(
                    itertools.islice(
                        nx.all_simple_paths(self.graph, "attacker", impact_id),
                        max_paths,
                    )
                )
            except nx.NetworkXError:
                continue

            for node_list in raw_paths:
                labels = [
                    self.graph.nodes[n].get("label", n) for n in node_list
                ]
                risk = self._score_path(node_list)
                desc = " → ".join(labels)
                paths.append(AttackPath(
                    nodes=node_list,
                    labels=labels,
                    risk_score=round(risk, 2),
                    description=desc,
                ))

        # Sort highest risk first
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        self._paths = paths
        return paths

    def _score_path(self, node_list: List[str]) -> float:
        """
        Score a single path.

        Risk = max_node_severity × Π(edge_probabilities)
        """
        if len(node_list) < 2:
            return 0.0

        max_severity = 0.0
        prob_product = 1.0

        for n in node_list:
            node_risk = self.graph.nodes[n].get("risk", 0.0)
            if node_risk > max_severity:
                max_severity = node_risk

        for u, v in zip(node_list[:-1], node_list[1:]):
            edge_data = self.graph.edges[u, v]
            prob_product *= edge_data.get("probability", 0.5)

        return max_severity * prob_product

    # ── Risk aggregation ─────────────────────────────────────────────────

    def compute_risk_summary(self) -> Dict:
        """
        Aggregate risk across all paths.
        """
        if not self._paths:
            self.compute_all_paths()

        if not self._paths:
            return {
                "overall_risk": 0.0,
                "risk_level": "none",
                "total_paths": 0,
                "critical_paths": 0,
                "high_paths": 0,
                "max_path_risk": 0.0,
                "avg_path_risk": 0.0,
            }

        scores = [p.risk_score for p in self._paths]
        max_risk = max(scores)
        avg_risk = sum(scores) / len(scores)

        if max_risk >= 8.0:
            level = "critical"
        elif max_risk >= 6.0:
            level = "high"
        elif max_risk >= 4.0:
            level = "medium"
        else:
            level = "low"

        return {
            "overall_risk": round(max_risk, 2),
            "risk_level": level,
            "total_paths": len(self._paths),
            "critical_paths": sum(1 for s in scores if s >= 8.0),
            "high_paths": sum(1 for s in scores if 6.0 <= s < 8.0),
            "max_path_risk": round(max_risk, 2),
            "avg_path_risk": round(avg_risk, 2),
        }

    # ── Serialization (for API / frontend) ───────────────────────────────

    def to_dict(self) -> Dict:
        """
        Serialize the full graph + computed paths for the frontend.
        Returns react-flow compatible node/edge format.
        """
        if not self._paths:
            self.compute_all_paths()

        nodes = []
        for nid, data in self.graph.nodes(data=True):
            nodes.append({
                "id": nid,
                "label": data.get("label", nid),
                "type": data.get("node_type", "unknown"),
                "risk": data.get("risk", 0.0),
                "color": data.get("color", "#6b7280"),
                "severity": data.get("severity", ""),
                "category": data.get("category", ""),
                "confidence": data.get("confidence", 0.0),
                "description": data.get("description", ""),
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "from": u,
                "to": v,
                "label": data.get("label", ""),
                "type": data.get("edge_type", ""),
                "probability": data.get("probability", 0.5),
            })

        paths_serialized = [
            {
                "nodes": p.nodes,
                "labels": p.labels,
                "risk_score": p.risk_score,
                "description": p.description,
            }
            for p in self._paths[:50]   # cap for API payload size
        ]

        risk_summary = self.compute_risk_summary()

        return {
            "nodes": nodes,
            "edges": edges,
            "paths": paths_serialized,
            "risk_summary": risk_summary,
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
        }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _category_color(category: str) -> str:
    return {
        "authentication": "#f59e0b",
        "admin_panel": "#ef4444",
        "file_upload": "#8b5cf6",
        "api_endpoint": "#3b82f6",
        "data_retrieval": "#10b981",
        "user_data": "#06b6d4",
        "unknown": "#6b7280",
    }.get(category, "#6b7280")


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#991b1b",
        "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b",
        "LOW": "#10b981",
        "INFO": "#6b7280",
    }.get(severity, "#6b7280")
