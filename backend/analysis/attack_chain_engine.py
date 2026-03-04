"""
Aegis AI — Autonomous Attack Chain Discovery Engine

Instead of reporting individual vulnerabilities in isolation, this engine
discovers **multi-step attack chains** — realistic exploitation paths that
combine multiple findings into end-to-end compromise scenarios.

This is the same approach used by:
  • Palo Alto Cortex XSIAM
  • Wiz Cloud Security Graph
  • Microsoft Defender Security Graph
  • Google Chronicle

Architecture:
  Existing AttackGraph (NetworkX DiGraph) ──► AttackChainEngine
    → discovers all simple paths from attacker ➜ impact nodes
    → enriches each path with CVE intelligence
    → scores chains based on CVSS, probability, and chain length
    → classifies severity (CRITICAL / HIGH / MEDIUM / LOW)
    → identifies the most dangerous multi-step exploitation scenarios
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import networkx as nx


# ── Chain severity thresholds ────────────────────────────────────────────────

CHAIN_SEVERITY_THRESHOLDS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
}

# Bonus multipliers for chain characteristics
VULN_CHAIN_BONUS = 5          # per vulnerability node in the chain
IMPACT_CHAIN_BONUS = 10       # per impact node reached
CVE_MATCH_BONUS = 3           # per CVE-enriched vulnerability
MULTI_VULN_MULTIPLIER = 1.5   # applied when chain chains 2+ different vuln types
RCE_BONUS = 15                # if chain reaches Remote Code Execution
DATA_EXFIL_BONUS = 8          # if chain reaches Data Exfiltration


@dataclass
class AttackChain:
    """A single multi-step attack chain."""
    id: int
    path: List[str]              # node IDs
    labels: List[str]            # human-readable labels
    length: int                  # number of nodes
    score: float                 # composite severity score
    severity: str                # CRITICAL / HIGH / MEDIUM / LOW
    description: str             # readable chain narrative
    vulnerabilities: List[Dict]  # vuln nodes in this chain
    impacts: List[Dict]          # impact nodes reached
    endpoints: List[Dict]        # endpoint nodes traversed
    cve_ids: List[str]           # CVE IDs associated with chain vulns
    probability: float           # overall exploitation probability


class AttackChainEngine:
    """
    Discovers autonomous multi-step attack chains from the attack graph.

    Uses the existing NetworkX DiGraph built by AttackGraph to find
    every path from an attacker entry node to an impact node, then
    scores and ranks them to surface the most dangerous real-world
    exploitation scenarios.
    """

    def __init__(self, graph: nx.DiGraph, cve_intel: Optional[Dict] = None):
        """
        Args:
            graph: NetworkX DiGraph from AttackGraph.graph
            cve_intel: Optional dict mapping vuln_type → CVE intelligence
                       (from CVEEngine enrichment results)
        """
        self.graph = graph
        self.cve_intel = cve_intel or {}
        self._chains: List[AttackChain] = []
        self._stats: Dict = {}

    # ──────────────────────────────────────────────────────────────────────
    # Core discovery
    # ──────────────────────────────────────────────────────────────────────

    def discover_attack_chains(
        self,
        max_depth: int = 8,
        max_chains: int = 500,
        min_score: float = 0.0,
    ) -> List[AttackChain]:
        """
        Discover all multi-step attack chains.

        1. Find attacker entry nodes and impact sink nodes
        2. Enumerate all simple paths (capped by depth/count)
        3. Score each chain
        4. Classify severity
        5. Sort by score descending
        """
        attackers = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "attacker" or d.get("type") == "attacker"
        ]
        impacts = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "impact" or d.get("type") == "impact"
        ]

        if not attackers or not impacts:
            self._chains = []
            self._compute_stats()
            return []

        raw_paths: List[List[str]] = []
        for attacker in attackers:
            for impact in impacts:
                try:
                    paths = nx.all_simple_paths(
                        self.graph,
                        source=attacker,
                        target=impact,
                        cutoff=max_depth,
                    )
                    raw_paths.extend(
                        itertools.islice(paths, max_chains - len(raw_paths))
                    )
                except nx.NetworkXError:
                    continue
                if len(raw_paths) >= max_chains:
                    break

        # Build AttackChain objects
        chains: List[AttackChain] = []
        for idx, path in enumerate(raw_paths):
            chain = self._build_chain(idx + 1, path)
            if chain.score >= min_score:
                chains.append(chain)

        # Sort by score (highest first)
        chains.sort(key=lambda c: c.score, reverse=True)

        # Re-number after sort
        for i, c in enumerate(chains):
            c.id = i + 1

        self._chains = chains
        self._compute_stats()
        return chains

    # ──────────────────────────────────────────────────────────────────────
    # Chain building + scoring
    # ──────────────────────────────────────────────────────────────────────

    def _build_chain(self, chain_id: int, path: List[str]) -> AttackChain:
        """Build a single AttackChain from a raw node path."""
        labels = []
        vulnerabilities = []
        impacts = []
        endpoints = []
        cve_ids = []
        vuln_types_seen = set()

        for node_id in path:
            data = self.graph.nodes[node_id]
            label = data.get("label", node_id)
            labels.append(label)
            node_type = data.get("node_type", data.get("type", "unknown"))

            if node_type == "vulnerability":
                vtype = data.get("vuln_type", "")
                vuln_types_seen.add(vtype)
                vuln_info = {
                    "id": node_id,
                    "label": label,
                    "vuln_type": vtype,
                    "severity": data.get("severity", "MEDIUM"),
                    "risk": data.get("risk", 5.0),
                    "confidence": data.get("confidence", 0.5),
                }
                # Attach CVE IDs if available
                if vtype in self.cve_intel:
                    intel = self.cve_intel[vtype]
                    vuln_cves = [c["id"] for c in intel.get("cve_examples", [])]
                    vuln_info["cve_ids"] = vuln_cves
                    vuln_info["cvss_score"] = intel.get("cvss_score", 0.0)
                    cve_ids.extend(vuln_cves)
                vulnerabilities.append(vuln_info)

            elif node_type == "impact":
                impacts.append({
                    "id": node_id,
                    "label": label,
                    "severity": data.get("risk", 8.0),
                    "description": data.get("description", ""),
                })

            elif node_type == "endpoint":
                endpoints.append({
                    "id": node_id,
                    "label": label,
                    "category": data.get("category", "unknown"),
                    "risk": data.get("risk", 0.5),
                })

        # Score
        score = self._score_chain(path, vulnerabilities, impacts, vuln_types_seen)
        severity = self._classify_severity(score)
        probability = self._compute_probability(path)

        # Build human-readable description
        description = self._narrate_chain(labels, vulnerabilities, impacts)

        return AttackChain(
            id=chain_id,
            path=path,
            labels=labels,
            length=len(path),
            score=round(score, 2),
            severity=severity,
            description=description,
            vulnerabilities=vulnerabilities,
            impacts=impacts,
            endpoints=endpoints,
            cve_ids=list(set(cve_ids)),  # dedupe
            probability=round(probability, 4),
        )

    def _score_chain(
        self,
        path: List[str],
        vulnerabilities: List[Dict],
        impacts: List[Dict],
        vuln_types: set,
    ) -> float:
        """
        Composite scoring:
          base = Σ vuln_risk + Σ impact_severity
          + bonus per vuln/impact node
          + CVE match bonus
          + multi-vuln-type multiplier
          + RCE / data-exfil bonuses
        """
        base = 0.0

        # Vulnerability contributions
        for v in vulnerabilities:
            base += v.get("risk", 5.0)
            base += VULN_CHAIN_BONUS
            if v.get("cve_ids"):
                base += CVE_MATCH_BONUS

        # Impact contributions
        for imp in impacts:
            base += imp.get("severity", 8.0)
            base += IMPACT_CHAIN_BONUS
            imp_label = imp.get("label", "").lower()
            if "remote code execution" in imp_label or "rce" in imp_label:
                base += RCE_BONUS
            if "data exfiltration" in imp_label or "data breach" in imp_label:
                base += DATA_EXFIL_BONUS

        # Multi-vulnerability-type multiplier
        if len(vuln_types) >= 2:
            base *= MULTI_VULN_MULTIPLIER

        return base

    def _compute_probability(self, path: List[str]) -> float:
        """Product of edge probabilities along the path."""
        if len(path) < 2:
            return 0.0
        prob = 1.0
        for u, v in zip(path[:-1], path[1:]):
            edge = self.graph.edges.get((u, v), {})
            prob *= edge.get("probability", 0.5)
        return prob

    @staticmethod
    def _classify_severity(score: float) -> str:
        if score >= CHAIN_SEVERITY_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        if score >= CHAIN_SEVERITY_THRESHOLDS["HIGH"]:
            return "HIGH"
        if score >= CHAIN_SEVERITY_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _narrate_chain(
        labels: List[str],
        vulnerabilities: List[Dict],
        impacts: List[Dict],
    ) -> str:
        """Build a human-readable attack narrative."""
        parts = []
        for lbl in labels:
            parts.append(lbl)

        narrative = " → ".join(parts)

        if vulnerabilities and impacts:
            vuln_names = ", ".join(v["label"] for v in vulnerabilities)
            impact_names = ", ".join(i["label"] for i in impacts)
            narrative += (
                f"  ⟨exploits {vuln_names} → achieves {impact_names}⟩"
            )

        return narrative

    # ──────────────────────────────────────────────────────────────────────
    # Statistics
    # ──────────────────────────────────────────────────────────────────────

    def _compute_stats(self):
        chains = self._chains
        if not chains:
            self._stats = {
                "total_chains": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "max_score": 0.0,
                "avg_score": 0.0,
                "avg_length": 0.0,
                "unique_cves": 0,
                "most_dangerous": None,
            }
            return

        scores = [c.score for c in chains]
        self._stats = {
            "total_chains": len(chains),
            "critical": sum(1 for c in chains if c.severity == "CRITICAL"),
            "high": sum(1 for c in chains if c.severity == "HIGH"),
            "medium": sum(1 for c in chains if c.severity == "MEDIUM"),
            "low": sum(1 for c in chains if c.severity == "LOW"),
            "max_score": round(max(scores), 2),
            "avg_score": round(sum(scores) / len(scores), 2),
            "avg_length": round(sum(c.length for c in chains) / len(chains), 1),
            "unique_cves": len(set(cve for c in chains for cve in c.cve_ids)),
            "most_dangerous": chains[0].description if chains else None,
        }

    def get_stats(self) -> Dict:
        return dict(self._stats)

    def get_chains(self) -> List[AttackChain]:
        return list(self._chains)

    def get_chains_by_severity(self, severity: str) -> List[AttackChain]:
        return [c for c in self._chains if c.severity == severity.upper()]

    # ──────────────────────────────────────────────────────────────────────
    # Serialization (for API / frontend)
    # ──────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict:
        """Serialize all chains + stats for the API response."""
        return {
            "chains": [
                {
                    "id": c.id,
                    "path": c.path,
                    "labels": c.labels,
                    "length": c.length,
                    "score": c.score,
                    "severity": c.severity,
                    "description": c.description,
                    "vulnerabilities": c.vulnerabilities,
                    "impacts": c.impacts,
                    "endpoints": c.endpoints,
                    "cve_ids": c.cve_ids,
                    "probability": c.probability,
                }
                for c in self._chains[:100]  # cap payload
            ],
            "stats": self._stats,
        }
