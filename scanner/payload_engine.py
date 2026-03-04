"""
Aegis AI — Payload Engine
Manages vulnerability test payloads and injection strategies.
Each vulnerability type has specialized injection and detection logic.
"""
import re
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from scanner.request_engine import RequestEngine, HttpResponse
from utils.config import config, PAYLOADS
from utils.logger import get_logger

logger = get_logger(__name__, "EXPLOIT")


@dataclass
class TestResult:
    """Result of a single vulnerability test."""
    url: str
    vuln_type: str
    payload: str
    parameter: str
    http_method: str
    baseline_response: Optional[HttpResponse]
    test_response: Optional[HttpResponse]
    is_vulnerable: bool = False
    confidence: float = 0.0
    evidence: str = ""
    anomaly_score: float = 0.0


class SQLiTester:
    """
    Tests for SQL Injection vulnerabilities.
    Detects error-based, boolean-based, and time-based SQLi.
    """

    # Patterns that indicate SQL errors in responses
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"ORA-[0-9]{5}",  # Oracle
        r"SQLiteException",
        r"System\.Data\.SQLite",
        r"Unclosed quotation mark",  # MSSQL
        r"Microsoft OLE DB Provider for SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"PostgreSQL.*ERROR",
        r"ERROR:\s+syntax error at or near",
        r"psycopg2\.ProgrammingError",
        r"You have an error in your SQL syntax",
        r"Syntax error in string in query expression",
    ]

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test a parameter for SQL injection vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        for payload in PAYLOADS["sql_injection"][:5]:  # Test top 5 payloads
            # Inject into URL parameter
            test_url = self._inject_url_param(url, parameter, payload)
            response = await engine.get(test_url)

            if response.error:
                continue

            # Check for SQL errors in response
            is_vuln, confidence, evidence = self._analyze_response(
                baseline, response, payload
            )

            result = TestResult(
                url=url,
                vuln_type="sql_injection",
                payload=payload,
                parameter=parameter,
                http_method="GET",
                baseline_response=baseline,
                test_response=response,
                is_vulnerable=is_vuln,
                confidence=confidence,
                evidence=evidence,
            )
            results.append(result)

            if is_vuln and confidence > 0.7:
                break  # Stop testing if high confidence found

        return results

    def _inject_url_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _analyze_response(
        self,
        baseline: HttpResponse,
        test: HttpResponse,
        payload: str,
    ) -> Tuple[bool, float, str]:
        """Analyze response for SQL injection indicators."""
        body_lower = test.body.lower()

        # Check for SQL error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, test.body, re.IGNORECASE):
                return True, 0.90, f"SQL error pattern detected: {pattern}"

        # Check for significant response size change (boolean-based)
        if baseline:
            size_ratio = len(test.body) / max(len(baseline.body), 1)
            if size_ratio > 2.0 or size_ratio < 0.5:
                return True, 0.60, f"Significant response size change (ratio: {size_ratio:.2f})"

        # Generic database error keywords
        generic_errors = ["database error", "sql error", "syntax error", "query failed"]
        for err in generic_errors:
            if err in body_lower:
                return True, 0.70, f"Database error keyword found: {err}"

        return False, 0.0, ""


class XSSTester:
    """
    Tests for Cross-Site Scripting (XSS) vulnerabilities.
    Detects reflected and stored XSS patterns.
    """

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test a parameter for XSS vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        for payload in PAYLOADS["xss"][:4]:
            test_url = self._inject_url_param(url, parameter, payload)
            response = await engine.get(test_url)

            if response.error:
                continue

            is_vuln, confidence, evidence = self._analyze_response(
                response, payload
            )

            results.append(TestResult(
                url=url,
                vuln_type="xss",
                payload=payload,
                parameter=parameter,
                http_method="GET",
                baseline_response=baseline,
                test_response=response,
                is_vulnerable=is_vuln,
                confidence=confidence,
                evidence=evidence,
            ))

            if is_vuln and confidence > 0.8:
                break

        return results

    def _inject_url_param(self, url: str, param: str, payload: str) -> str:
        from urllib.parse import quote
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _analyze_response(
        self, response: HttpResponse, payload: str
    ) -> Tuple[bool, float, str]:
        """Check if XSS payload is reflected in response."""
        # Check for unescaped reflection of payload
        if payload in response.body:
            return True, 0.85, f"Payload reflected unencoded in response"

        # Check for partial reflection (tag may be intact)
        if "<script>" in response.body.lower() and "alert" in response.body.lower():
            return True, 0.75, "Script tag with alert found in response"

        # Check for event handler injection
        if "onerror=" in response.body.lower() or "onload=" in response.body.lower():
            return True, 0.65, "Event handler injected into response"

        return False, 0.0, ""


class OpenRedirectTester:
    """Tests for Open Redirect vulnerabilities."""

    REDIRECT_PARAMS = [
        "redirect", "redirect_to", "redirectUrl", "next", "url",
        "return", "returnTo", "returnUrl", "goto", "destination",
        "target", "to", "link", "ref", "continue",
    ]

    async def test(
        self, url: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test for open redirect vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        for param in self.REDIRECT_PARAMS:
            for payload in PAYLOADS["open_redirect"][:2]:
                test_url = self._inject_redirect_param(url, param, payload)
                response = await engine.get(test_url, allow_redirects=False)

                if response.error:
                    continue

                is_vuln, confidence, evidence = self._analyze_response(
                    response, payload
                )

                if is_vuln:
                    results.append(TestResult(
                        url=url,
                        vuln_type="open_redirect",
                        payload=payload,
                        parameter=param,
                        http_method="GET",
                        baseline_response=baseline,
                        test_response=response,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=evidence,
                    ))

        return results

    def _inject_redirect_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _analyze_response(
        self, response: HttpResponse, payload: str
    ) -> Tuple[bool, float, str]:
        """Check if redirect points to injected URL."""
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            if "evil.com" in location or payload in location:
                return True, 0.95, f"Redirect to: {location}"
        return False, 0.0, ""


class SecurityHeaderChecker:
    """Checks for missing or misconfigured security headers."""

    async def check(self, url: str, engine: RequestEngine) -> List[TestResult]:
        """Check security headers on the target."""
        results = []
        response = await engine.get(url)

        if response.error:
            return results

        from utils.config import SECURITY_HEADERS

        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            header_present = any(
                k.lower() == header_lower for k in response.headers.keys()
            )

            if not header_present:
                results.append(TestResult(
                    url=url,
                    vuln_type="missing_security_header",
                    payload="",
                    parameter=header,
                    http_method="GET",
                    baseline_response=None,
                    test_response=response,
                    is_vulnerable=True,
                    confidence=1.0,
                    evidence=f"Missing header: {header} — {info['description']}",
                ))

        # Check for insecure server disclosure
        server = response.headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            results.append(TestResult(
                url=url,
                vuln_type="server_version_disclosure",
                payload="",
                parameter="Server",
                http_method="GET",
                baseline_response=None,
                test_response=response,
                is_vulnerable=True,
                confidence=0.85,
                evidence=f"Server version disclosed: {server}",
            ))

        return results


class SSTITester:
    """Tests for Server-Side Template Injection (SSTI)."""

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test for SSTI vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        for payload in PAYLOADS["ssti"]:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)

            if response.error:
                continue

            # Check if math expression was evaluated
            if "49" in response.body and "{{7*7}}" not in response.body:
                results.append(TestResult(
                    url=url,
                    vuln_type="ssti",
                    payload=payload,
                    parameter=parameter,
                    http_method="GET",
                    baseline_response=baseline,
                    test_response=response,
                    is_vulnerable=True,
                    confidence=0.80,
                    evidence="Template expression evaluated: 7*7=49",
                ))
                break

        return results

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()
