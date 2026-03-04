"""
Aegis AI — Vulnerability Evidence Engine

Upgrade 4 — Every finding must carry concrete proof of exploitation.

For each vulnerability the evidence object includes:
  • request   — the exact HTTP request sent
  • response  — response snippet with highlighted match
  • timing    — baseline vs payload response time
  • diff      — fingerprint diff summary
  • proof     — human-readable explanation of *why* this is a vulnerability

This module is a data builder, not a scanner — it packages evidence that
was already collected during scanning + verification into a standardised
structure suitable for reports and the frontend.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "EVIDENCE")


@dataclass
class VulnerabilityEvidence:
    """Standardised evidence packet for a single finding."""
    vuln_type: str
    url: str
    parameter: str
    payload: str

    # Request proof
    request_method: str = "GET"
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    # Response proof
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: str = ""           # first ~300 chars of body
    response_highlight: str = ""         # the exact substring that proves the vuln

    # Timing proof
    baseline_time_ms: float = 0.0
    payload_time_ms: float = 0.0
    time_delta_ms: float = 0.0

    # Fingerprint diff
    fingerprint_diff: Optional[Dict] = None

    # Verification
    verified: bool = False
    verification_stage: int = 0
    verification_technique: str = ""

    # Human-readable summary
    proof_summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.response_status,
                "headers": dict(list(self.response_headers.items())[:15]),
                "snippet": self.response_snippet,
                "highlight": self.response_highlight,
            },
            "timing": {
                "baseline_ms": round(self.baseline_time_ms, 1),
                "payload_ms": round(self.payload_time_ms, 1),
                "delta_ms": round(self.time_delta_ms, 1),
            },
            "fingerprint_diff": self.fingerprint_diff,
            "verification": {
                "verified": self.verified,
                "stage": self.verification_stage,
                "technique": self.verification_technique,
            },
            "proof_summary": self.proof_summary,
        }


class EvidenceBuilder:
    """
    Builds standardised VulnerabilityEvidence from scan / verification data.
    """

    @staticmethod
    def build(
        vuln_type: str,
        url: str,
        parameter: str,
        payload: str,
        *,
        baseline_response=None,
        test_response=None,
        verification_result=None,
        fingerprint_diff: Optional[Dict] = None,
    ) -> VulnerabilityEvidence:
        """
        Build evidence from raw scan data.

        Args:
            vuln_type: sql_injection | xss | open_redirect | ...
            url: target URL
            parameter: vulnerable parameter
            payload: the payload that triggered the finding
            baseline_response: HttpResponse for clean request (optional)
            test_response: HttpResponse for payload request (optional)
            verification_result: VerificationResult (optional)
            fingerprint_diff: FingerprintDiff dict (optional)
        """
        ev = VulnerabilityEvidence(
            vuln_type=vuln_type,
            url=url,
            parameter=parameter,
            payload=payload,
        )

        # Request evidence
        ev.request_method = "GET"
        ev.request_url = url
        if parameter and payload:
            ev.request_url = f"{url}?{parameter}={payload}"

        # Response evidence
        if test_response:
            ev.response_status = test_response.status_code
            ev.response_headers = dict(test_response.headers)
            ev.response_snippet = test_response.body[:500]
            ev.payload_time_ms = test_response.response_time_ms

            # Try to find the payload or error in the response
            ev.response_highlight = EvidenceBuilder._extract_highlight(
                test_response.body, payload, vuln_type
            )

        # Timing evidence
        if baseline_response:
            ev.baseline_time_ms = baseline_response.response_time_ms
            ev.time_delta_ms = ev.payload_time_ms - ev.baseline_time_ms

        # Fingerprint diff
        if fingerprint_diff:
            ev.fingerprint_diff = fingerprint_diff

        # Verification evidence
        if verification_result:
            ev.verified = verification_result.verified
            ev.verification_stage = verification_result.stage_reached
            ev.verification_technique = verification_result.technique

        # Build human-readable proof summary
        ev.proof_summary = EvidenceBuilder._build_proof_summary(ev)

        return ev

    @staticmethod
    def _extract_highlight(body: str, payload: str, vuln_type: str) -> str:
        """Extract the most relevant snippet from the response body."""
        # Try exact payload reflection
        idx = body.find(payload)
        if idx >= 0:
            start = max(0, idx - 30)
            end = min(len(body), idx + len(payload) + 30)
            return body[start:end]

        # Try error keywords for SQLi
        if vuln_type == "sql_injection":
            import re
            for kw in ("SQL syntax", "mysql_", "ORA-", "PostgreSQL", "Unclosed quotation"):
                m = re.search(re.escape(kw), body, re.I)
                if m:
                    start = max(0, m.start() - 20)
                    end = min(len(body), m.end() + 50)
                    return body[start:end]

        return ""

    @staticmethod
    def _build_proof_summary(ev: VulnerabilityEvidence) -> str:
        """Build a human-readable proof summary."""
        parts = []

        if ev.verified:
            parts.append(f"✅ VERIFIED via {ev.verification_technique} (stage {ev.verification_stage})")
        else:
            parts.append("❓ Unverified — manual review recommended")

        parts.append(f"Request: {ev.request_method} {ev.request_url}")
        parts.append(f"Response: HTTP {ev.response_status}")

        if ev.response_highlight:
            parts.append(f"Highlight: …{ev.response_highlight}…")

        if ev.time_delta_ms > 1000:
            parts.append(
                f"Timing: baseline {ev.baseline_time_ms:.0f}ms → "
                f"payload {ev.payload_time_ms:.0f}ms (Δ{ev.time_delta_ms:.0f}ms)"
            )

        if ev.fingerprint_diff and ev.fingerprint_diff.get("significant"):
            parts.append(
                f"Fingerprint: length_delta={ev.fingerprint_diff.get('length_delta')}, "
                f"hash_match={ev.fingerprint_diff.get('hash_match')}"
            )

        return "\n".join(parts)
