"""
Aegis AI — Risk Scoring Engine

Computes a single **Security Score (0–100)** that summarizes the overall
risk posture of a scanned target.  Security teams need one number.

Scoring model:
  Start at 100 (perfect).  Deduct points for:
    - Critical attack chains    (-15 each)
    - High attack chains        (-8 each)
    - Medium attack chains      (-4 each)
    - Low attack chains         (-1 each)
    - Critical vulnerabilities  (-10 each, capped)
    - High vulnerabilities      (-5 each, capped)
    - Average CVSS penalty      (scaled 0–15)
    - High-value impacts (RCE, data-exfil)  (-5 each)

Result includes:
  • score         (0–100)
  • risk_level    (CRITICAL / HIGH / MEDIUM / LOW / SECURE)
  • breakdown     (per-category deductions)
  • recommendations
"""
from __future__ import annotations
from typing import Dict, List, Optional


# ── Risk-level thresholds ────────────────────────────────────────────────────

RISK_LEVELS = [
    (0,  "CRITICAL",  "Immediate remediation required — active exploitation risk"),
    (30, "HIGH",      "Significant vulnerabilities detected — prioritise fixes"),
    (60, "MEDIUM",    "Moderate issues exist — schedule remediation"),
    (80, "LOW",       "Minor findings only — continue monitoring"),
    (90, "SECURE",    "No significant risks detected"),
]


class RiskScoringEngine:
    """
    Computes a holistic security score for a completed scan.

    Usage:
        engine = RiskScoringEngine()
        result = engine.compute(scan_state)
        # result["score"]      → 62
        # result["risk_level"] → "HIGH"
    """

    def compute(self, scan_state: Dict) -> Dict:
        """
        Compute the security score from a full scan state dict.

        Args:
            scan_state: the orchestrator's scan state containing
                        vulnerabilities, attack_chains, attack_graph, etc.
        """
        breakdown: Dict[str, float] = {}
        score = 100.0

        # ── 1. Attack chain deductions ───────────────────────────────
        chains = scan_state.get("attack_chains", {})
        chain_stats = chains.get("stats", {}) if isinstance(chains, dict) else {}

        crit_chains = chain_stats.get("critical", 0)
        high_chains = chain_stats.get("high", 0)
        med_chains  = chain_stats.get("medium", 0)
        low_chains  = chain_stats.get("low", 0)

        chain_penalty = (
            crit_chains * 15
            + high_chains * 8
            + med_chains * 4
            + low_chains * 1
        )
        chain_penalty = min(chain_penalty, 50)  # cap at 50 pts
        breakdown["attack_chains"] = round(chain_penalty, 2)
        score -= chain_penalty

        # ── 2. Vulnerability deductions ──────────────────────────────
        vulns = scan_state.get("vulnerabilities", [])
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cvss_values: List[float] = []

        for v in vulns:
            sev = v.get("severity", "LOW").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cve_intel = v.get("cve_intel", {})
            if cve_intel and cve_intel.get("enriched"):
                cvss_values.append(cve_intel.get("cvss_score", 0.0))

        vuln_penalty = (
            min(sev_counts["CRITICAL"], 5) * 10
            + min(sev_counts["HIGH"], 8) * 5
            + min(sev_counts["MEDIUM"], 10) * 2
            + min(sev_counts["LOW"], 15) * 0.5
        )
        vuln_penalty = min(vuln_penalty, 40)
        breakdown["vulnerabilities"] = round(vuln_penalty, 2)
        score -= vuln_penalty

        # ── 3. Average CVSS penalty ──────────────────────────────────
        if cvss_values:
            avg_cvss = sum(cvss_values) / len(cvss_values)
            cvss_penalty = (avg_cvss / 10.0) * 15  # scale 0-10 → 0-15
        else:
            avg_cvss = 0.0
            cvss_penalty = 0.0
        cvss_penalty = min(cvss_penalty, 15)
        breakdown["cvss_average"] = round(cvss_penalty, 2)
        score -= cvss_penalty

        # ── 4. Impact-type penalty ───────────────────────────────────
        graph = scan_state.get("attack_graph", {})
        impact_nodes = [
            n for n in graph.get("nodes", [])
            if n.get("type") == "impact"
        ]
        high_value_impacts = 0
        for imp in impact_nodes:
            label = imp.get("label", "").lower()
            if any(kw in label for kw in [
                "remote code execution", "rce", "database compromise",
                "data exfiltration", "admin access", "full system",
            ]):
                high_value_impacts += 1

        impact_penalty = min(high_value_impacts * 5, 15)
        breakdown["high_value_impacts"] = round(impact_penalty, 2)
        score -= impact_penalty

        # ── Clamp ────────────────────────────────────────────────────
        score = max(0.0, min(100.0, score))
        score = round(score, 1)

        risk_level, risk_description = self._classify(score)

        # ── Recommendations ──────────────────────────────────────────
        recommendations = self._generate_recommendations(
            sev_counts, crit_chains, high_chains, high_value_impacts, avg_cvss
        )

        return {
            "score": score,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "breakdown": breakdown,
            "details": {
                "total_vulnerabilities": len(vulns),
                "severity_counts": sev_counts,
                "total_attack_chains": chain_stats.get("total_chains", 0),
                "chain_severity": {
                    "critical": crit_chains,
                    "high": high_chains,
                    "medium": med_chains,
                    "low": low_chains,
                },
                "avg_cvss": round(avg_cvss, 2),
                "high_value_impacts": high_value_impacts,
                "total_deductions": round(100 - score, 1),
            },
            "recommendations": recommendations,
        }

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _classify(score: float):
        for threshold, level, desc in RISK_LEVELS:
            if score <= threshold:
                return level, desc
        return "SECURE", "No significant risks detected"

    @staticmethod
    def _generate_recommendations(
        sev_counts: Dict,
        crit_chains: int,
        high_chains: int,
        high_impacts: int,
        avg_cvss: float,
    ) -> List[str]:
        recs = []
        if sev_counts.get("CRITICAL", 0) > 0:
            recs.append(
                f"Fix {sev_counts['CRITICAL']} CRITICAL vulnerabilities immediately — "
                f"these allow direct exploitation."
            )
        if crit_chains > 0:
            recs.append(
                f"{crit_chains} critical attack chain(s) detected — "
                f"attackers can chain vulnerabilities for full compromise."
            )
        if high_impacts > 0:
            recs.append(
                f"{high_impacts} high-value impact(s) reachable (RCE, DB compromise) — "
                f"isolate and patch affected services."
            )
        if avg_cvss >= 7.0:
            recs.append(
                f"Average CVSS score is {avg_cvss:.1f} — "
                f"overall vulnerability severity is high."
            )
        if sev_counts.get("HIGH", 0) > 0:
            recs.append(
                f"Address {sev_counts['HIGH']} HIGH severity findings in the next sprint."
            )
        if sev_counts.get("MEDIUM", 0) > 0:
            recs.append(
                f"Schedule remediation for {sev_counts['MEDIUM']} MEDIUM findings."
            )
        if not recs:
            recs.append("No critical issues found — maintain security monitoring and regular scans.")
        return recs
