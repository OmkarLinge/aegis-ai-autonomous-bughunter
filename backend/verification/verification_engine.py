"""
Aegis AI — Multi-Stage Verification Engine (Orchestrator)

Coordinates specialised verifiers for each vulnerability type.
Called by the exploit agent AFTER initial detection to confirm or reject
each finding with multi-stage proof.

Upgrade 1 — Multi-Stage Vulnerability Verification Engine
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from scanner.request_engine import RequestEngine
from backend.verification.sql_injection_verifier import SQLInjectionVerifier, SQLiVerificationResult
from backend.verification.xss_verifier import XSSVerifier, XSSVerificationResult
from backend.verification.redirect_verifier import OpenRedirectVerifier, RedirectVerificationResult
from utils.logger import get_logger

logger = get_logger(__name__, "VERIFY")


@dataclass
class VerificationResult:
    """Unified verification result across all vuln types."""
    vuln_type: str
    verified: bool = False
    confidence: float = 0.0
    technique: str = ""
    stage_reached: int = 0
    evidence: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    details: Optional[Dict] = None


class VerificationEngine:
    """
    Orchestrates multi-stage verification for all vulnerability types.

    Usage:
        engine = VerificationEngine()
        result = await engine.verify("sql_injection", url, param, request_engine)
        if result.verified:
            # confirmed finding
    """

    def __init__(self):
        self.sqli_verifier = SQLInjectionVerifier()
        self.xss_verifier = XSSVerifier()
        self.redirect_verifier = OpenRedirectVerifier()
        self._stats = {"total": 0, "verified": 0, "rejected": 0}

    async def verify(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        engine: RequestEngine,
    ) -> VerificationResult:
        """
        Run multi-stage verification for the given vulnerability type.

        Args:
            vuln_type:  sql_injection | xss | open_redirect | ssti | ...
            url:        target URL
            parameter:  vulnerable parameter name
            engine:     RequestEngine for HTTP requests

        Returns:
            VerificationResult with verification status and evidence.
        """
        self._stats["total"] += 1

        result = VerificationResult(vuln_type=vuln_type)

        if vuln_type == "sql_injection":
            r = await self.sqli_verifier.verify(url, parameter, engine)
            result.verified = r.verified
            result.confidence = r.confidence
            result.technique = r.technique
            result.stage_reached = r.stage_reached
            result.evidence = r.evidence
            result.request_evidence = r.request_evidence
            result.response_evidence = r.response_evidence
            result.details = {
                "dbms_hint": r.dbms_hint,
                "boolean_diff": r.boolean_diff,
            }

        elif vuln_type == "xss":
            r = await self.xss_verifier.verify(url, parameter, engine)
            result.verified = r.verified
            result.confidence = r.confidence
            result.technique = r.technique
            result.stage_reached = r.stage_reached
            result.evidence = r.evidence
            result.request_evidence = r.request_evidence
            result.response_evidence = r.response_evidence
            result.details = {
                "context": r.context,
                "csp_blocks": r.csp_blocks,
            }

        elif vuln_type == "open_redirect":
            r = await self.redirect_verifier.verify(url, engine)
            result.verified = r.verified
            result.confidence = r.confidence
            result.stage_reached = r.stage_reached
            result.evidence = r.evidence
            result.request_evidence = r.request_evidence
            result.response_evidence = r.response_evidence
            result.details = {
                "redirect_url": r.redirect_url,
                "external_domain": r.external_domain,
            }

        elif vuln_type in ("ssti",):
            # SSTI uses inline verification in payload_engine already
            result.confidence = 0.5
            result.evidence = "SSTI verification is inline in payload engine"

        elif vuln_type in ("missing_security_header", "server_version_disclosure"):
            # These are always confirmed by definition
            result.verified = True
            result.confidence = 1.0
            result.evidence = "Header-based finding — always confirmed"

        else:
            logger.debug(f"No specialised verifier for {vuln_type}")
            result.confidence = 0.3

        if result.verified:
            self._stats["verified"] += 1
        else:
            self._stats["rejected"] += 1

        logger.info(
            "[VERIFY] %s on %s param=%s → %s (confidence=%.2f, stage=%d)",
            vuln_type, url, parameter,
            "VERIFIED" if result.verified else "UNVERIFIED",
            result.confidence, result.stage_reached,
        )

        return result

    def get_stats(self) -> Dict:
        return dict(self._stats)
