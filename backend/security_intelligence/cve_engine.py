"""
Aegis AI — CVE Intelligence Engine
Enriches scanner findings with real-world CVE data, CVSS scores,
impact analysis, and mitigation guidance from the CVE database.
"""

from datetime import datetime
from backend.security_intelligence.cve_database import CVE_DATABASE


class CVEEngine:
    """
    Maps detected vulnerability types to known CVE references and
    provides CVSS-scored intelligence for each finding.
    """

    def __init__(self):
        self.db = CVE_DATABASE
        self.enrichment_stats = {
            "total_processed": 0,
            "matched": 0,
            "unmatched": 0,
            "timestamp": None,
        }

    # ------------------------------------------------------------------
    # Core enrichment
    # ------------------------------------------------------------------

    def enrich_vulnerability(self, vuln_type: str) -> dict:
        """
        Look up a vulnerability type and return CVE intelligence.

        Returns a dict with:
          - cve_examples   : list of related CVE dicts
          - cvss_score     : float (0.0 – 10.0)
          - cvss_vector    : CVSS v3.1 vector string
          - severity_label : Critical / High / Medium / Low / Info
          - impact         : human-readable impact description
          - mitigation     : recommended fix
          - references     : useful OWASP / CWE links
          - enriched       : bool — True if a match was found
        """
        self.enrichment_stats["total_processed"] += 1

        # Normalise the key (lowercase, underscores)
        key = vuln_type.lower().replace(" ", "_").replace("-", "_")

        record = self.db.get(key)
        if record:
            self.enrichment_stats["matched"] += 1
            return {
                "cve_examples": record["cve_examples"],
                "cvss_score": record["cvss_score"],
                "cvss_vector": record.get("cvss_vector", ""),
                "severity_label": record.get("severity_label", self._severity_from_cvss(record["cvss_score"])),
                "impact": record["impact"],
                "mitigation": record["mitigation"],
                "references": record.get("references", []),
                "enriched": True,
            }

        # No direct match — try a fuzzy keyword match
        for db_key, record in self.db.items():
            if db_key in key or key in db_key:
                self.enrichment_stats["matched"] += 1
                return {
                    "cve_examples": record["cve_examples"],
                    "cvss_score": record["cvss_score"],
                    "cvss_vector": record.get("cvss_vector", ""),
                    "severity_label": record.get("severity_label", self._severity_from_cvss(record["cvss_score"])),
                    "impact": record["impact"],
                    "mitigation": record["mitigation"],
                    "references": record.get("references", []),
                    "enriched": True,
                }

        # Fallback — no match in database
        self.enrichment_stats["unmatched"] += 1
        return {
            "cve_examples": [],
            "cvss_score": 0.0,
            "cvss_vector": "",
            "severity_label": "Info",
            "impact": "Impact assessment not available for this vulnerability type.",
            "mitigation": "Review OWASP guidelines for general mitigation strategies.",
            "references": ["https://owasp.org/www-project-top-ten/"],
            "enriched": False,
        }

    # ------------------------------------------------------------------
    # Batch enrichment for full scan results
    # ------------------------------------------------------------------

    def enrich_scan_results(self, vulnerabilities: list[dict]) -> list[dict]:
        """
        Enrich a list of vulnerability dicts in-place and return them.
        Each dict gets new keys: cve_examples, cvss_score, etc.
        """
        self.enrichment_stats["timestamp"] = datetime.utcnow().isoformat()

        for vuln in vulnerabilities:
            vuln_type = vuln.get("vuln_type", vuln.get("type", "unknown"))
            intel = self.enrich_vulnerability(vuln_type)
            vuln["cve_intel"] = intel

        return vulnerabilities

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_from_cvss(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.1:
            return "Low"
        return "Info"

    def get_stats(self) -> dict:
        return dict(self.enrichment_stats)

    def get_supported_types(self) -> list[str]:
        return list(self.db.keys())
