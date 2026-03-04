"""
Aegis AI — Response Fingerprinting Engine

Upgrade 2 — Response Fingerprinting

Instead of comparing only status codes, build a multi-field fingerprint
for every HTTP response and compare them to detect suspicious differences.

Fingerprint fields:
  • status_code
  • content_length
  • body_hash (MD5)
  • header_set (sorted header names)
  • redirect_location
  • response_time_ms
  • content_type
  • body_structure_hash (tag-structure-only hash for HTML)

Two fingerprints are "significantly different" when:
  – hash differs AND (length delta > 5% OR status differs)
  – OR redirect_location changed
  – OR new error-status (4xx/5xx) appeared
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional, Set

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from scanner.request_engine import HttpResponse
from utils.logger import get_logger

logger = get_logger(__name__, "FINGERPRINT")


# ── Type alias ───────────────────────────────────────────────────────────────
FingerprintDict = Dict[str, object]
FingerprintDiff = Dict[str, object]


class ResponseFingerprint:
    """
    Build and compare response fingerprints.

    All methods are static / class-level — no instance state needed.
    """

    # ── Build ────────────────────────────────────────────────────────────

    @staticmethod
    def build(response: HttpResponse) -> FingerprintDict:
        """Create a fingerprint dict from an HttpResponse."""
        body = response.body or ""
        header_keys = sorted(k.lower() for k in response.headers.keys())

        return {
            "status": response.status_code,
            "length": len(body),
            "hash": hashlib.md5(body.encode(errors="replace")).hexdigest(),
            "headers": header_keys,
            "header_set": set(header_keys),
            "redirect_location": response.headers.get("location", ""),
            "response_time_ms": response.response_time_ms,
            "content_type": response.headers.get("content-type", ""),
            "structure_hash": ResponseFingerprint._structure_hash(body),
        }

    # ── Compare ──────────────────────────────────────────────────────────

    @staticmethod
    def compare(fp_a: FingerprintDict, fp_b: FingerprintDict) -> FingerprintDiff:
        """
        Compare two fingerprints and return a diff dict.

        The diff includes a boolean ``significant`` flag that indicates
        whether the responses are meaningfully different — i.e. the
        target likely processed the payload.
        """
        status_changed = fp_a["status"] != fp_b["status"]
        hash_match = fp_a["hash"] == fp_b["hash"]
        length_delta = abs(fp_a["length"] - fp_b["length"])
        length_pct = length_delta / max(fp_a["length"], 1) * 100

        # Header diff
        set_a: Set[str] = fp_a.get("header_set", set())
        set_b: Set[str] = fp_b.get("header_set", set())
        new_headers = sorted(set_b - set_a)
        removed_headers = sorted(set_a - set_b)

        # Redirect diff
        redirect_changed = fp_a.get("redirect_location") != fp_b.get("redirect_location")

        # Timing diff
        time_a = fp_a.get("response_time_ms", 0)
        time_b = fp_b.get("response_time_ms", 0)
        time_delta = abs(time_b - time_a)

        # Structure hash diff (HTML tag skeleton)
        structure_match = fp_a.get("structure_hash") == fp_b.get("structure_hash")

        # ── Significance decision ────────────────────────────────────────
        significant = False

        # Hash differs + meaningful size or status change
        if not hash_match and (length_pct > 5 or status_changed):
            significant = True

        # Redirect changed
        if redirect_changed:
            significant = True

        # New error status appeared
        if not status_changed:
            pass
        elif fp_b["status"] >= 400 and fp_a["status"] < 400:
            significant = True
        elif fp_a["status"] >= 400 and fp_b["status"] < 400:
            significant = True

        # Huge timing anomaly (possible time-based injection)
        if time_delta > 3000:
            significant = True

        return {
            "significant": significant,
            "status_changed": status_changed,
            "hash_match": hash_match,
            "length_delta": length_delta,
            "length_pct": round(length_pct, 2),
            "new_headers": new_headers,
            "removed_headers": removed_headers,
            "redirect_changed": redirect_changed,
            "time_delta_ms": round(time_delta, 1),
            "structure_match": structure_match,
        }

    # ── Bulk compare helper ──────────────────────────────────────────────

    @staticmethod
    def compare_baseline(
        baseline: HttpResponse,
        test_responses: list[HttpResponse],
    ) -> list[FingerprintDiff]:
        """Compare a baseline against a list of test responses."""
        bp = ResponseFingerprint.build(baseline)
        return [
            ResponseFingerprint.compare(bp, ResponseFingerprint.build(r))
            for r in test_responses
        ]

    # ── Internal ─────────────────────────────────────────────────────────

    @staticmethod
    def _structure_hash(body: str) -> str:
        """
        Hash the HTML tag structure only (strip all text content).
        This detects when the *shape* of the page changes even if the
        text content is similar.
        """
        tags = re.findall(r"</?[a-zA-Z][a-zA-Z0-9]*", body)
        skeleton = "".join(tags)
        return hashlib.md5(skeleton.encode()).hexdigest()
