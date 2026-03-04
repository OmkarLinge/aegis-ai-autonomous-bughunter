"""
Aegis AI — False Positive Suppression System

Upgrade 5 — Confidence-based filtering.

Multi-signal scoring:
    Signal                  Weight
    ─────────────────────── ──────
    payload reflected       +0.20
    error pattern detected  +0.30
    response diff (fp)      +0.20
    exploit confirmed       +0.30

Only report if  confidence ≥ REPORT_THRESHOLD (0.70).
Findings below threshold are demoted to "informational".

This replaces the simple > 0.5 filter in deduplication_engine
with a richer, signal-level scoring system that runs BEFORE dedup.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "FP-FILTER")


# ── Thresholds ───────────────────────────────────────────────────────────────

REPORT_THRESHOLD = 0.70       # confirmed / suspicious
INFO_THRESHOLD = 0.40         # informational
# Below INFO_THRESHOLD → suppressed entirely


# ── Signal weights ───────────────────────────────────────────────────────────

SIGNAL_WEIGHTS = {
    "payload_reflected":   0.20,
    "error_detected":      0.30,
    "response_diff":       0.20,
    "exploit_confirmed":   0.30,
}


@dataclass
class ScoredFinding:
    """A vulnerability finding with multi-signal confidence score."""
    original: Dict                        # the raw finding dict
    signals: Dict[str, bool] = field(default_factory=dict)
    signal_score: float = 0.0
    classification: str = "suppressed"    # confirmed | suspicious | informational | suppressed
    original_confidence: float = 0.0


class FalsePositiveFilter:
    """
    Multi-signal confidence scoring and false-positive suppression.

    Usage:
        fpf = FalsePositiveFilter()
        results = fpf.process(raw_findings)
        # results → list of ScoredFinding with classification
    """

    def __init__(
        self,
        report_threshold: float = REPORT_THRESHOLD,
        info_threshold: float = INFO_THRESHOLD,
    ):
        self.report_threshold = report_threshold
        self.info_threshold = info_threshold
        self._stats = {
            "total_input": 0,
            "confirmed": 0,
            "suspicious": 0,
            "informational": 0,
            "suppressed": 0,
        }

    def process(self, findings: List[Dict]) -> List[ScoredFinding]:
        """
        Score and classify a list of raw finding dicts.

        Each finding dict is expected to have at least:
          vuln_type, confidence, verified, evidence
        And optionally:
          response_analysis (or payload_reflected, error_pattern etc.)
        """
        self._stats["total_input"] = len(findings)
        scored: List[ScoredFinding] = []

        for f in findings:
            sf = self._score(f)
            scored.append(sf)
            self._stats[sf.classification] += 1

        logger.info(
            "[FP-FILTER] %d input → %d confirmed, %d suspicious, "
            "%d informational, %d suppressed",
            self._stats["total_input"],
            self._stats["confirmed"],
            self._stats["suspicious"],
            self._stats["informational"],
            self._stats["suppressed"],
        )

        return scored

    def get_confirmed(self, scored: List[ScoredFinding]) -> List[Dict]:
        """Return only confirmed + suspicious findings (reportable)."""
        return [
            s.original for s in scored
            if s.classification in ("confirmed", "suspicious")
        ]

    def get_informational(self, scored: List[ScoredFinding]) -> List[Dict]:
        """Return informational findings (low-confidence appendix)."""
        return [s.original for s in scored if s.classification == "informational"]

    def get_stats(self) -> Dict:
        return dict(self._stats)

    # ── Internal ─────────────────────────────────────────────────────────

    def _score(self, f: Dict) -> ScoredFinding:
        """Compute multi-signal score for a single finding."""
        sf = ScoredFinding(original=f, original_confidence=f.get("confidence", 0))

        # Extract signals
        signals = {
            "payload_reflected": self._check_reflection(f),
            "error_detected": self._check_error(f),
            "response_diff": self._check_diff(f),
            "exploit_confirmed": bool(f.get("verified", False)),
        }
        sf.signals = signals

        # Weighted score
        score = sum(
            SIGNAL_WEIGHTS[sig] for sig, present in signals.items() if present
        )
        sf.signal_score = round(score, 3)

        # Blend with original confidence (70% signal, 30% original)
        blended = 0.7 * sf.signal_score + 0.3 * sf.original_confidence
        sf.signal_score = round(blended, 3)

        # Classify
        if sf.signal_score >= self.report_threshold and signals["exploit_confirmed"]:
            sf.classification = "confirmed"
        elif sf.signal_score >= self.report_threshold:
            sf.classification = "suspicious"
        elif sf.signal_score >= self.info_threshold:
            sf.classification = "informational"
        else:
            sf.classification = "suppressed"

        # Header-based findings are always at least informational
        if f.get("vuln_type") in ("missing_security_header", "server_version_disclosure"):
            if sf.classification == "suppressed":
                sf.classification = "informational"

        # Update the finding's confidence with the blended score
        f["confidence"] = sf.signal_score

        return sf

    # ── Signal detectors ─────────────────────────────────────────────────

    @staticmethod
    def _check_reflection(f: Dict) -> bool:
        """Check if payload was reflected in the response."""
        # From response_analysis object
        ra = f.get("response_analysis")
        if ra and isinstance(ra, dict):
            return ra.get("payload_reflected", False)
        if ra and hasattr(ra, "payload_reflected"):
            return ra.payload_reflected

        # From evidence text
        evidence = f.get("evidence", "")
        if "reflected" in evidence.lower():
            return True

        return False

    @staticmethod
    def _check_error(f: Dict) -> bool:
        """Check if a database / template error was detected."""
        evidence = f.get("evidence", "").lower()
        for kw in ("sql error", "database error", "syntax error",
                    "template expression", "error pattern confirmed",
                    "dbms error"):
            if kw in evidence:
                return True
        return False

    @staticmethod
    def _check_diff(f: Dict) -> bool:
        """Check if a significant response diff was detected."""
        evidence = f.get("evidence", "").lower()
        if "size anomaly" in evidence or "boolean differential" in evidence:
            return True
        if "fingerprint" in evidence and "changed" in evidence:
            return True
        if "time-based" in evidence:
            return True
        # From response_analysis
        ra = f.get("response_analysis")
        if ra and isinstance(ra, dict):
            delta = ra.get("content_length_delta", 0)
            if abs(delta) > 200:
                return True
        return False
