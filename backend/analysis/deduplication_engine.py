"""
Aegis AI — Vulnerability Deduplication & Ranking Engine

Solves two critical problems:
1. Duplicate vulnerabilities  — multiple payloads for the same flaw get merged
2. False positives           — low-confidence findings are filtered out

Pipeline:
  raw findings → dedup → false-positive filter → rank → final report-ready list

Example:
  474 raw findings → 12 confirmed, unique, ranked vulnerabilities.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ── Constants ────────────────────────────────────────────────────────────────

CONFIDENCE_THRESHOLD = 0.5          # Anything below this is discarded
HIGH_CONFIDENCE_THRESHOLD = 0.75    # Considered "confirmed"

# CVSS v3.1 base scores per vuln type (industry standard values)
CVSS_SCORES: Dict[str, float] = {
    "sql_injection":              9.8,
    "ssti":                       9.1,
    "auth_bypass":                9.8,
    "file_upload_bypass":         9.0,
    "path_traversal":             7.5,
    "xss":                        6.1,
    "open_redirect":              6.1,
    "idor":                       6.5,
    "server_version_disclosure":  5.3,
    "missing_security_header":    4.0,
}

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class DeduplicatedVulnerability:
    """A single *real* vulnerability with all its evidence merged."""

    # Identity
    vuln_type: str
    endpoint: str                   # path portion, e.g. /api/login
    parameters: List[str]           # all affected params

    # Merged evidence
    payloads_tested: List[str]
    evidence_snippets: List[str]
    evidence_count: int

    # Scoring
    confidence: float               # best confidence from all test cases
    avg_confidence: float           # mean confidence
    severity: str
    cvss_score: float
    risk_score: float               # composite ranking score (0-100)

    # Metadata (carried over from best test case)
    title: str
    description: str
    impact: str
    remediation: str
    cwe_id: str
    http_method: str
    status_code: int
    url: str

    # ML / anomaly signals
    ml_prediction: str
    ml_confidence: float
    anomaly_score: float

    # Request / response evidence (from best test case)
    request_evidence: str = ""
    response_evidence: str = ""

    # CVE intel (if enriched)
    cve_intel: Optional[Dict] = None

    # All raw finding IDs that were merged
    merged_ids: List[int] = field(default_factory=list)


# ── Engine ───────────────────────────────────────────────────────────────────

class DeduplicationEngine:
    """
    Takes raw vulnerability findings and produces a clean, ranked list.

    Algorithm:
    1. Group by (vuln_type, endpoint_path, parameter_set)
    2. Merge each group into a single DeduplicatedVulnerability
    3. Apply false-positive filter (confidence < threshold → discard)
    4. Compute composite risk score for ranking
    5. Sort by risk score descending
    """

    def __init__(
        self,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
        enable_fp_filter: bool = True,
    ):
        self.confidence_threshold = confidence_threshold
        self.enable_fp_filter = enable_fp_filter
        self._raw_count = 0
        self._deduped_count = 0
        self._filtered_count = 0

    # ── Public API ───────────────────────────────────────────────────────

    def process(
        self,
        raw_findings: List[Dict],
        attack_chains: Optional[Dict] = None,
    ) -> List[Dict]:
        """
        Main pipeline: dedup → filter → rank → serialise.

        Args:
            raw_findings:  list of vulnerability dicts from the exploit agent
            attack_chains: chain data (used for ranking boost)

        Returns:
            List of clean, ranked vulnerability dicts ready for the frontend/report.
        """
        self._raw_count = len(raw_findings)

        # 1) Group
        groups = self._group(raw_findings)

        # 2) Merge each group
        merged: List[DeduplicatedVulnerability] = []
        for key, members in groups.items():
            merged.append(self._merge(key, members))

        # 3) False-positive filter
        if self.enable_fp_filter:
            before = len(merged)
            merged = [v for v in merged if v.confidence >= self.confidence_threshold]
            self._filtered_count = before - len(merged)
        else:
            self._filtered_count = 0

        self._deduped_count = len(merged)

        # 4) Rank
        chain_type_set = self._extract_chain_types(attack_chains)
        for v in merged:
            v.risk_score = self._compute_risk_score(v, chain_type_set)

        # 5) Sort by risk (highest first)
        merged.sort(key=lambda v: v.risk_score, reverse=True)

        # 6) Serialise
        return [self._to_dict(v, rank=i + 1) for i, v in enumerate(merged)]

    def get_stats(self) -> Dict:
        return {
            "raw_count": self._raw_count,
            "deduplicated_count": self._deduped_count,
            "false_positives_removed": self._filtered_count,
            "reduction_pct": (
                round((1 - self._deduped_count / max(self._raw_count, 1)) * 100, 1)
            ),
        }

    # ── Grouping ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_path(url: str) -> str:
        """Extract path from full URL."""
        parsed = urlparse(url)
        return parsed.path or "/"

    @staticmethod
    def _group_key(vuln: Dict) -> Tuple[str, str]:
        """
        Group key = (vuln_type, endpoint_path).
        Parameters are merged inside the group.
        """
        path = DeduplicationEngine._normalise_path(vuln.get("url", "/"))
        return (vuln.get("vuln_type", "unknown"), path)

    def _group(self, findings: List[Dict]) -> Dict[Tuple, List[Dict]]:
        groups: Dict[Tuple, List[Dict]] = defaultdict(list)
        for f in findings:
            key = self._group_key(f)
            groups[key].append(f)
        return groups

    # ── Merging ──────────────────────────────────────────────────────────

    def _merge(
        self,
        key: Tuple[str, str],
        members: List[Dict],
    ) -> DeduplicatedVulnerability:
        """Merge a group of raw findings into one DeduplicatedVulnerability."""

        vuln_type, endpoint = key

        # Gather unique params, payloads, evidence
        params = list({m.get("parameter", "") for m in members if m.get("parameter")})
        payloads = list({m.get("payload", "") for m in members if m.get("payload")})
        evidence_snippets = list(
            {m.get("evidence", "") for m in members if m.get("evidence")}
        )

        # Pick the "best" member (highest confidence) for metadata
        best = max(members, key=lambda m: m.get("confidence", 0))

        confidences = [m.get("confidence", 0) for m in members]
        best_confidence = max(confidences)
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        severity = best.get("severity", "LOW")
        cvss = CVSS_SCORES.get(vuln_type, 4.0)

        # Build request / response evidence from best hit
        req_evidence = ""
        resp_evidence = ""
        if best.get("payload") and best.get("url"):
            method = best.get("http_method", "GET")
            req_evidence = f"{method} {best['url']}?{best.get('parameter', '')}={best.get('payload', '')}"
        if best.get("response_snippet"):
            resp_evidence = best["response_snippet"][:500]

        return DeduplicatedVulnerability(
            vuln_type=vuln_type,
            endpoint=endpoint,
            parameters=params,
            payloads_tested=payloads,
            evidence_snippets=evidence_snippets,
            evidence_count=len(members),
            confidence=best_confidence,
            avg_confidence=round(avg_confidence, 3),
            severity=severity,
            cvss_score=cvss,
            risk_score=0.0,  # computed later
            title=best.get("title", vuln_type.replace("_", " ").title()),
            description=best.get("description", ""),
            impact=best.get("impact", ""),
            remediation=best.get("remediation", ""),
            cwe_id=best.get("cwe_id", ""),
            http_method=best.get("http_method", "GET"),
            status_code=best.get("status_code", 0),
            url=best.get("url", ""),
            ml_prediction=best.get("ml_prediction", ""),
            ml_confidence=best.get("ml_confidence", 0),
            anomaly_score=best.get("anomaly_score", 0),
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            cve_intel=best.get("cve_intel"),
            merged_ids=[m.get("id", 0) for m in members],
        )

    # ── Risk Scoring / Ranking (Step 9) ──────────────────────────────────

    @staticmethod
    def _compute_risk_score(
        v: DeduplicatedVulnerability,
        chain_types: set,
    ) -> float:
        """
        Composite risk score 0-100.

        Formula:
          risk = CVSS * 0.40
               + confidence * 0.25
               + severity_weight * 0.15
               + chain_bonus * 0.10
               + evidence_depth * 0.10
        """
        # CVSS component (0-10 → 0-40)
        cvss_component = (v.cvss_score / 10.0) * 40

        # Confidence component (0-1 → 0-25)
        conf_component = v.confidence * 25

        # Severity component (0-15)
        sev_component = SEVERITY_WEIGHT.get(v.severity, 0.25) * 15

        # Chain bonus: if this vuln type appears in a discovered attack chain
        chain_bonus = 10.0 if v.vuln_type in chain_types else 0.0

        # Evidence depth: more payloads tested = higher trust
        ev_depth = min(10.0, (v.evidence_count / 5.0) * 10)

        return round(
            cvss_component + conf_component + sev_component + chain_bonus + ev_depth,
            1,
        )

    @staticmethod
    def _extract_chain_types(chains: Optional[Dict]) -> set:
        """Extract set of vuln_types that appear in attack chains."""
        types = set()
        if not chains:
            return types
        for chain in chains.get("chains", []):
            for step in chain.get("steps", []):
                vtype = step.get("vuln_type") or step.get("type", "")
                if vtype:
                    types.add(vtype)
        return types

    # ── Serialisation ────────────────────────────────────────────────────

    @staticmethod
    def _to_dict(v: DeduplicatedVulnerability, rank: int) -> Dict:
        return {
            "rank": rank,
            "vuln_type": v.vuln_type,
            "title": v.title,
            "endpoint": v.endpoint,
            "parameters": v.parameters,
            "payloads_tested": v.payloads_tested,
            "evidence_snippets": v.evidence_snippets,
            "evidence_count": v.evidence_count,
            "confidence": v.confidence,
            "avg_confidence": v.avg_confidence,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "risk_score": v.risk_score,
            "description": v.description,
            "impact": v.impact,
            "remediation": v.remediation,
            "cwe_id": v.cwe_id,
            "http_method": v.http_method,
            "status_code": v.status_code,
            "url": v.url,
            "ml_prediction": v.ml_prediction,
            "ml_confidence": v.ml_confidence,
            "anomaly_score": v.anomaly_score,
            "request_evidence": v.request_evidence,
            "response_evidence": v.response_evidence,
            "cve_intel": v.cve_intel,
            "merged_ids": v.merged_ids,
        }
