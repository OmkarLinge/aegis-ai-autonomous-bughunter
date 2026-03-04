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
class ResponseAnalysis:
    """Detailed response analysis for a single test (Step 5)."""
    status_code_changed: bool = False
    content_length_delta: int = 0
    header_changed: bool = False
    payload_reflected: bool = False
    response_time_delta_ms: float = 0.0
    error_pattern_detected: bool = False
    redirect_detected: bool = False
    new_headers: List[str] = field(default_factory=list)
    removed_headers: List[str] = field(default_factory=list)


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
    verified: bool = False                          # Step 2: confirmed by verification
    response_analysis: Optional[ResponseAnalysis] = None  # Step 5: detailed analysis
    request_evidence: str = ""                      # Step 8: full request for proof
    response_evidence: str = ""                     # Step 8: full response for proof


def _analyse_response_diff(
    baseline: Optional[HttpResponse],
    test: HttpResponse,
    payload: str,
) -> ResponseAnalysis:
    """Compare baseline vs test response and extract analysis features (Step 5)."""
    analysis = ResponseAnalysis()

    if baseline:
        analysis.status_code_changed = baseline.status_code != test.status_code
        analysis.content_length_delta = len(test.body) - len(baseline.body)
        analysis.response_time_delta_ms = test.response_time_ms - baseline.response_time_ms

        baseline_keys = set(k.lower() for k in baseline.headers)
        test_keys = set(k.lower() for k in test.headers)
        analysis.new_headers = sorted(test_keys - baseline_keys)
        analysis.removed_headers = sorted(baseline_keys - test_keys)
        analysis.header_changed = bool(analysis.new_headers or analysis.removed_headers)

    analysis.payload_reflected = payload in test.body
    analysis.redirect_detected = test.status_code in (301, 302, 303, 307, 308)

    return analysis


def _build_confidence(
    payload_reflected: bool = False,
    status_changed: bool = False,
    headers_changed: bool = False,
    exploit_confirmed: bool = False,
    error_pattern: bool = False,
    size_anomaly: bool = False,
    time_anomaly: bool = False,
) -> float:
    """Multi-signal confidence scoring (Step 3)."""
    score = 0.0
    if payload_reflected:
        score += 0.25
    if status_changed:
        score += 0.15
    if headers_changed:
        score += 0.10
    if exploit_confirmed:
        score += 0.30
    if error_pattern:
        score += 0.15
    if size_anomaly:
        score += 0.10
    if time_anomaly:
        score += 0.10
    return min(round(score, 2), 1.0)


def _build_evidence_strings(
    url: str, method: str, param: str, payload: str,
    test: HttpResponse,
) -> Tuple[str, str]:
    """Build request/response evidence for proof (Step 8)."""
    req = f"{method} {url}?{param}={payload} HTTP/1.1"
    resp_lines = [f"HTTP/1.1 {test.status_code}"]
    for k, v in list(test.headers.items())[:10]:
        resp_lines.append(f"{k}: {v}")
    resp_lines.append("")
    resp_lines.append(test.body[:300])
    return req, "\n".join(resp_lines)


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

        for payload in PAYLOADS["sql_injection"][:5]:
            test_url = self._inject_url_param(url, parameter, payload)
            response = await engine.get(test_url)

            if response.error:
                continue

            # Analyse response diff (Step 5)
            analysis = _analyse_response_diff(baseline, response, payload)

            # Verify (Step 2) — require actual SQL error proof
            is_vuln, verified, evidence = self._verify(baseline, response, payload, analysis)

            # Multi-signal confidence (Step 3)
            confidence = _build_confidence(
                payload_reflected=analysis.payload_reflected,
                status_changed=analysis.status_code_changed,
                headers_changed=analysis.header_changed,
                exploit_confirmed=verified,
                error_pattern=analysis.error_pattern_detected,
                size_anomaly=abs(analysis.content_length_delta) > 500,
                time_anomaly=analysis.response_time_delta_ms > 2000,
            )

            # Evidence strings (Step 8)
            req_ev, resp_ev = _build_evidence_strings(url, "GET", parameter, payload, response)

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
                verified=verified,
                response_analysis=analysis,
                request_evidence=req_ev,
                response_evidence=resp_ev,
            )
            results.append(result)

            if is_vuln and confidence > 0.7:
                break

        return results

    def _inject_url_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _verify(
        self,
        baseline: Optional[HttpResponse],
        test: HttpResponse,
        payload: str,
        analysis: ResponseAnalysis,
    ) -> Tuple[bool, bool, str]:
        """Step 2: Verify SQL injection with concrete proof."""
        body = test.body

        # 1) Strong proof: known SQL error regex
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                analysis.error_pattern_detected = True
                return True, True, f"SQL error pattern confirmed: {pattern}"

        # 2) Generic DB error keywords
        body_lower = body.lower()
        for err in ("database error", "sql error", "syntax error", "query failed"):
            if err in body_lower:
                analysis.error_pattern_detected = True
                return True, True, f"Database error keyword confirmed: {err}"

        # 3) Boolean-based: significant body-size change (suspicious, not confirmed)
        if baseline:
            size_ratio = len(body) / max(len(baseline.body), 1)
            if size_ratio > 2.0 or size_ratio < 0.5:
                return True, False, f"Response size anomaly (ratio: {size_ratio:.2f}) — unconfirmed"

        # 4) Time-based blind: unusually slow response
        if analysis.response_time_delta_ms > 4000:
            return True, False, f"Time-based anomaly ({analysis.response_time_delta_ms:.0f}ms delta) — possible blind SQLi"

        return False, False, ""


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

            analysis = _analyse_response_diff(baseline, response, payload)
            is_vuln, verified, evidence = self._verify(response, payload, analysis)

            confidence = _build_confidence(
                payload_reflected=analysis.payload_reflected,
                status_changed=analysis.status_code_changed,
                headers_changed=analysis.header_changed,
                exploit_confirmed=verified,
                error_pattern=False,
                size_anomaly=abs(analysis.content_length_delta) > 200,
            )

            req_ev, resp_ev = _build_evidence_strings(url, "GET", parameter, payload, response)

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
                verified=verified,
                response_analysis=analysis,
                request_evidence=req_ev,
                response_evidence=resp_ev,
            ))

            if is_vuln and confidence > 0.8:
                break

        return results

    def _inject_url_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _verify(
        self, response: HttpResponse, payload: str, analysis: ResponseAnalysis,
    ) -> Tuple[bool, bool, str]:
        """Step 2: Verify XSS with concrete proof."""
        body_lower = response.body.lower()

        # Check CSP header — if present, XSS is mitigated even if reflected
        csp = response.headers.get("content-security-policy", "")
        has_csp = bool(csp)

        # 1) Full payload reflected unencoded
        if payload in response.body:
            if has_csp:
                return True, False, "Payload reflected but CSP may mitigate execution"
            return True, True, "Payload reflected unencoded in response — confirmed XSS"

        # 2) Script tag + alert() present
        if "<script>" in body_lower and "alert" in body_lower:
            return True, True, "Script tag with alert() found in response"

        # 3) Event handler injection
        for handler in ("onerror=", "onload=", "onmouseover=", "onfocus="):
            if handler in body_lower:
                return True, True, f"Event handler ({handler}) injected into response"

        # 4) Partial reflection (encoded) — suspicious but not confirmed
        import html as html_mod
        if html_mod.escape(payload) in response.body:
            return True, False, "Payload reflected HTML-encoded — browser may not execute"

        return False, False, ""


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
        target_domain = urlparse(url).netloc

        for param in self.REDIRECT_PARAMS:
            for payload in PAYLOADS["open_redirect"][:2]:
                test_url = self._inject_redirect_param(url, param, payload)
                response = await engine.get(test_url, allow_redirects=False)

                if response.error:
                    continue

                analysis = _analyse_response_diff(baseline, response, payload)
                is_vuln, verified, evidence = self._verify(
                    response, payload, target_domain, analysis
                )

                if is_vuln:
                    confidence = _build_confidence(
                        payload_reflected=analysis.payload_reflected,
                        status_changed=analysis.status_code_changed,
                        headers_changed=analysis.header_changed,
                        exploit_confirmed=verified,
                    )

                    req_ev, resp_ev = _build_evidence_strings(
                        url, "GET", param, payload, response
                    )

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
                        verified=verified,
                        response_analysis=analysis,
                        request_evidence=req_ev,
                        response_evidence=resp_ev,
                    ))

        return results

    def _inject_redirect_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _verify(
        self,
        response: HttpResponse,
        payload: str,
        target_domain: str,
        analysis: ResponseAnalysis,
    ) -> Tuple[bool, bool, str]:
        """
        Step 2: Verify open redirect properly.
        Correct behaviour:
          1. Check response status is 3xx
          2. Read Location header
          3. Confirm it redirects OUTSIDE the target domain
        """
        if response.status_code not in (301, 302, 303, 307, 308):
            return False, False, ""

        location = response.headers.get("location", "")
        if not location:
            return False, False, ""

        # Parse the Location header to check domain
        loc_parsed = urlparse(location)
        loc_domain = loc_parsed.netloc

        # Confirm redirect goes outside the target domain
        if loc_domain and loc_domain != target_domain:
            evidence = (
                f"Confirmed: {response.status_code} redirect to external domain\n"
                f"Location: {location}"
            )
            return True, True, evidence

        # Payload present in Location but same domain (relative)
        if payload in location:
            return True, False, f"Payload in Location header but same-domain: {location}"

        return False, False, ""


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

    # Multiple expression tests for stronger verification
    EXPRESSION_CHECKS = [
        ("{{7*7}}",  "49",   "7*7=49"),
        ("{{7*'7'}}", "7777777", "7*'7'=7777777 (Jinja2)"),
        ("${7*7}",   "49",   "${7*7}=49 (Mako/Freemarker)"),
    ]

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test for SSTI vulnerabilities with proper verification."""
        results = []
        baseline = await engine.get_baseline(url)

        for payload in PAYLOADS["ssti"]:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)

            if response.error:
                continue

            analysis = _analyse_response_diff(baseline, response, payload)

            # Verify: check multiple known expression outputs
            verified = False
            evidence = ""
            for expr, expected, desc in self.EXPRESSION_CHECKS:
                if expected in response.body and expr not in response.body:
                    verified = True
                    evidence = f"Template expression evaluated: {desc}"
                    break

            if not verified:
                # Fallback: generic "49" check
                if "49" in response.body and "{{7*7}}" not in response.body:
                    verified = True
                    evidence = "Template expression evaluated: 7*7=49"

            if verified:
                confidence = _build_confidence(
                    payload_reflected=False,
                    status_changed=analysis.status_code_changed,
                    exploit_confirmed=True,
                    headers_changed=analysis.header_changed,
                )
                req_ev, resp_ev = _build_evidence_strings(
                    url, "GET", parameter, payload, response
                )

                results.append(TestResult(
                    url=url,
                    vuln_type="ssti",
                    payload=payload,
                    parameter=parameter,
                    http_method="GET",
                    baseline_response=baseline,
                    test_response=response,
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=evidence,
                    verified=True,
                    response_analysis=analysis,
                    request_evidence=req_ev,
                    response_evidence=resp_ev,
                ))
                break

        return results

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()


# ═════════════════════════════════════════════════════════════════════════════
# Command Injection Tester
# ═════════════════════════════════════════════════════════════════════════════

class CommandInjectionTester:
    """
    Tests for OS Command Injection vulnerabilities.

    Detection strategies:
    1. Canary echo — inject '; echo aegis_cmdi_test' and look for output
    2. Time-based — inject '; sleep 5' and measure response delay
    3. Error-based — inject metacharacters and look for shell errors
    """

    # Canary payloads: if the canary string appears in response → confirmed
    CANARY = "aegis_cmdi_test"
    CANARY_PAYLOADS = [
        f"; echo {CANARY}",
        f"| echo {CANARY}",
        f"|| echo {CANARY}",
        f"&& echo {CANARY}",
        f"`echo {CANARY}`",
        f"$(echo {CANARY})",
        f"; echo {CANARY} ;",
        f"| echo {CANARY} |",
    ]

    # Time-based payloads
    TIME_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5 ||",
        "&& sleep 5 &&",
        "`sleep 5`",
        "$(sleep 5)",
    ]

    # Error trigger payloads
    ERROR_PAYLOADS = [";", "|", "||", "&&", "`", "$()"]

    SHELL_ERROR_PATTERNS = [
        re.compile(r"sh:\s*\d+:\s*Syntax error", re.I),
        re.compile(r"bash:\s*-c:\s*line", re.I),
        re.compile(r"cannot execute binary file", re.I),
        re.compile(r"/bin/sh:", re.I),
        re.compile(r"command not found", re.I),
        re.compile(r"syntax error near unexpected token", re.I),
        re.compile(r"No such file or directory", re.I),
        re.compile(r"Permission denied", re.I),
    ]

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test for command injection vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        # ── Strategy 1: Canary echo ──────────────────────────────────────
        for payload in self.CANARY_PAYLOADS:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)
            if response.error:
                continue

            analysis = _analyse_response_diff(baseline, response, payload)

            if self.CANARY in response.body:
                confidence = _build_confidence(
                    payload_reflected=True,
                    status_changed=analysis.status_code_changed,
                    exploit_confirmed=True,
                    headers_changed=analysis.header_changed,
                )
                req_ev, resp_ev = _build_evidence_strings(
                    url, "GET", parameter, payload, response
                )
                results.append(TestResult(
                    url=url,
                    vuln_type="command_injection",
                    payload=payload,
                    parameter=parameter,
                    http_method="GET",
                    baseline_response=baseline,
                    test_response=response,
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=f"Command output reflected: canary '{self.CANARY}' found in response",
                    verified=True,
                    response_analysis=analysis,
                    request_evidence=req_ev,
                    response_evidence=resp_ev,
                ))
                return results  # confirmed — no need to test more

        # ── Strategy 2: Time-based blind ─────────────────────────────────
        if baseline and not baseline.error:
            baseline_time = baseline.response_time_ms
            for payload in self.TIME_PAYLOADS:
                test_url = self._inject_param(url, parameter, payload)
                response = await engine.get(test_url)
                if response.error:
                    continue

                analysis = _analyse_response_diff(baseline, response, payload)
                time_delta = response.response_time_ms - baseline_time

                if time_delta > 4000:  # > 4s delay (expected ~5s)
                    confidence = _build_confidence(
                        payload_reflected=False,
                        status_changed=analysis.status_code_changed,
                        exploit_confirmed=True,
                        headers_changed=analysis.header_changed,
                    )
                    req_ev, resp_ev = _build_evidence_strings(
                        url, "GET", parameter, payload, response
                    )
                    results.append(TestResult(
                        url=url,
                        vuln_type="command_injection",
                        payload=payload,
                        parameter=parameter,
                        http_method="GET",
                        baseline_response=baseline,
                        test_response=response,
                        is_vulnerable=True,
                        confidence=max(confidence, 0.75),
                        evidence=(
                            f"Time-based command injection: "
                            f"baseline={baseline_time:.0f}ms → "
                            f"payload={response.response_time_ms:.0f}ms "
                            f"(Δ{time_delta:.0f}ms)"
                        ),
                        verified=True,
                        response_analysis=analysis,
                        request_evidence=req_ev,
                        response_evidence=resp_ev,
                    ))
                    return results

        # ── Strategy 3: Error-based ──────────────────────────────────────
        for payload in self.ERROR_PAYLOADS:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)
            if response.error:
                continue

            analysis = _analyse_response_diff(baseline, response, payload)
            for pattern in self.SHELL_ERROR_PATTERNS:
                if pattern.search(response.body):
                    confidence = _build_confidence(
                        payload_reflected=False,
                        status_changed=analysis.status_code_changed,
                        exploit_confirmed=False,
                        headers_changed=analysis.header_changed,
                    )
                    req_ev, resp_ev = _build_evidence_strings(
                        url, "GET", parameter, payload, response
                    )
                    results.append(TestResult(
                        url=url,
                        vuln_type="command_injection",
                        payload=payload,
                        parameter=parameter,
                        http_method="GET",
                        baseline_response=baseline,
                        test_response=response,
                        is_vulnerable=True,
                        confidence=max(confidence, 0.60),
                        evidence=f"Shell error pattern detected: {pattern.pattern}",
                        verified=False,
                        response_analysis=analysis,
                        request_evidence=req_ev,
                        response_evidence=resp_ev,
                    ))
                    return results

        return results

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()


# ═════════════════════════════════════════════════════════════════════════════
# Path Traversal / Local File Inclusion Tester
# ═════════════════════════════════════════════════════════════════════════════

class PathTraversalTester:
    """
    Tests for Path Traversal / Local File Inclusion (LFI) vulnerabilities.

    Detection strategies:
    1. Known file content — traverse to /etc/passwd, check for 'root:'
    2. Application file — traverse to known files like .env, config
    3. Null byte bypass — add %00 to bypass extension checks
    4. Encoding variants — double encoding, unicode dots
    """

    # Target files and their expected content
    TARGET_FILES = [
        ("../../../etc/passwd", "root:"),
        ("../../../../etc/passwd", "root:"),
        ("../../../../../etc/passwd", "root:"),
        ("../../../../../../etc/passwd", "root:"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
    ]

    # Encoding bypass variants
    ENCODING_VARIANTS = [
        ("..%2f..%2f..%2fetc/passwd", "root:"),
        ("..%252f..%252f..%252fetc/passwd", "root:"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%00/..%00/..%00/etc/passwd", "root:"),
    ]

    # Null byte bypass
    NULL_BYTE_VARIANTS = [
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd%00.html", "root:"),
        ("../../../etc/passwd%00.jpg", "root:"),
    ]

    # Application config traversal
    APP_CONFIG_TARGETS = [
        ("../.env", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"]),
        ("../../.env", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"]),
        ("../../../.env", ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"]),
        ("../../../wp-config.php", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
        ("../../../config/database.yml", ["adapter:", "database:", "username:"]),
    ]

    async def test(
        self, url: str, parameter: str, engine: RequestEngine
    ) -> List[TestResult]:
        """Test for path traversal vulnerabilities."""
        results = []
        baseline = await engine.get_baseline(url)

        # ── Strategy 1: Known system files ───────────────────────────────
        all_targets = self.TARGET_FILES + self.ENCODING_VARIANTS + self.NULL_BYTE_VARIANTS
        for payload, expected in all_targets:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)
            if response.error:
                continue

            analysis = _analyse_response_diff(baseline, response, payload)

            if expected in response.body:
                # Verify it's not just the word appearing normally
                # /etc/passwd should have "root:x:0:0" pattern
                is_genuine = self._verify_file_content(expected, response.body)
                if is_genuine:
                    confidence = _build_confidence(
                        payload_reflected=False,
                        status_changed=analysis.status_code_changed,
                        exploit_confirmed=True,
                        headers_changed=analysis.header_changed,
                    )
                    req_ev, resp_ev = _build_evidence_strings(
                        url, "GET", parameter, payload, response
                    )
                    results.append(TestResult(
                        url=url,
                        vuln_type="path_traversal",
                        payload=payload,
                        parameter=parameter,
                        http_method="GET",
                        baseline_response=baseline,
                        test_response=response,
                        is_vulnerable=True,
                        confidence=confidence,
                        evidence=f"File content confirmed: '{expected}' found via {payload}",
                        verified=True,
                        response_analysis=analysis,
                        request_evidence=req_ev,
                        response_evidence=resp_ev,
                    ))
                    return results  # confirmed

        # ── Strategy 2: Application config files ─────────────────────────
        for payload, markers in self.APP_CONFIG_TARGETS:
            test_url = self._inject_param(url, parameter, payload)
            response = await engine.get(test_url)
            if response.error:
                continue

            analysis = _analyse_response_diff(baseline, response, payload)
            matched = [m for m in markers if m in response.body]

            if len(matched) >= 2:  # at least 2 config markers
                confidence = _build_confidence(
                    payload_reflected=False,
                    status_changed=analysis.status_code_changed,
                    exploit_confirmed=True,
                    headers_changed=analysis.header_changed,
                )
                req_ev, resp_ev = _build_evidence_strings(
                    url, "GET", parameter, payload, response
                )
                results.append(TestResult(
                    url=url,
                    vuln_type="path_traversal",
                    payload=payload,
                    parameter=parameter,
                    http_method="GET",
                    baseline_response=baseline,
                    test_response=response,
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=f"Config file leaked via {payload} — markers: {matched}",
                    verified=True,
                    response_analysis=analysis,
                    request_evidence=req_ev,
                    response_evidence=resp_ev,
                ))
                return results

        return results

    @staticmethod
    def _verify_file_content(expected: str, body: str) -> bool:
        """Verify the file content is genuine, not a false match."""
        if expected == "root:":
            # /etc/passwd has specific format: root:x:0:0:...
            return bool(re.search(r"root:[x*]:0:0:", body))
        if expected == "[fonts]":
            # win.ini has [fonts] section
            return "[fonts]" in body and "[extensions]" in body.lower()
        return True

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()
