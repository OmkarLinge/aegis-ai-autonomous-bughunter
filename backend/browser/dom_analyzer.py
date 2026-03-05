"""
Aegis AI — DOM-Based Vulnerability Analyzer

Scans the rendered DOM and inline JavaScript for dangerous sinks that
could lead to DOM-based XSS, prototype pollution, and other
client-side vulnerabilities.

Detected sink categories:
- HTML injection sinks: innerHTML, outerHTML, insertAdjacentHTML, document.write
- Script execution sinks: eval, setTimeout(string), setInterval(string), Function()
- URL sinks: location.href, location.assign, window.open, document.location
- Storage sinks: postMessage misuse, localStorage injection
- Prototype pollution indicators: __proto__, constructor.prototype
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from utils.logger import get_logger

logger = get_logger(__name__, "DOM")


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class DOMSink:
    """A potential DOM-based vulnerability sink."""
    sink_type: str                     # innerHTML | eval | document.write | etc.
    category: str                      # html_injection | script_exec | url_sink | storage
    severity: str                      # HIGH | MEDIUM | LOW
    code_snippet: str                  # surrounding code context
    line_number: int = 0
    source_url: str = ""               # which script contained it
    tainted_source: str = ""           # user-controllable source if identified
    exploitable: bool = False          # True if source → sink path found
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_type": self.sink_type,
            "category": self.category,
            "severity": self.severity,
            "code_snippet": self.code_snippet[:300],
            "line_number": self.line_number,
            "source_url": self.source_url,
            "tainted_source": self.tainted_source,
            "exploitable": self.exploitable,
            "confidence": self.confidence,
        }


@dataclass
class DOMAnalysisResult:
    """Complete DOM analysis for a single page."""
    url: str
    sinks: List[DOMSink] = field(default_factory=list)
    total_scripts_analyzed: int = 0
    total_inline_scripts: int = 0
    total_external_scripts: int = 0
    dangerous_event_handlers: List[Dict[str, str]] = field(default_factory=list)
    postmessage_listeners: int = 0
    prototype_pollution_indicators: int = 0

    @property
    def high_severity_count(self) -> int:
        return sum(1 for s in self.sinks if s.severity == "HIGH")

    @property
    def exploitable_count(self) -> int:
        return sum(1 for s in self.sinks if s.exploitable)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "sink_count": len(self.sinks),
            "high_severity": self.high_severity_count,
            "exploitable": self.exploitable_count,
            "scripts_analyzed": self.total_scripts_analyzed,
            "sinks": [s.to_dict() for s in self.sinks],
            "dangerous_event_handlers": self.dangerous_event_handlers[:20],
            "postmessage_listeners": self.postmessage_listeners,
            "prototype_pollution_indicators": self.prototype_pollution_indicators,
        }


# ── Sink pattern definitions ────────────────────────────────────────────────

# category → [ (sink_name, regex, severity, notes) ]
SINK_PATTERNS: Dict[str, List[Tuple[str, re.Pattern, str]]] = {
    "html_injection": [
        ("innerHTML",
         re.compile(r"""\.innerHTML\s*[+]?=\s*(?!['"`]\s*$)""", re.I),
         "HIGH"),
        ("outerHTML",
         re.compile(r"""\.outerHTML\s*[+]?=\s*(?!['"`]\s*$)""", re.I),
         "HIGH"),
        ("insertAdjacentHTML",
         re.compile(r"""\.insertAdjacentHTML\s*\(""", re.I),
         "HIGH"),
        ("document.write",
         re.compile(r"""document\.write(?:ln)?\s*\(""", re.I),
         "HIGH"),
        ("document.writeln",
         re.compile(r"""document\.writeln\s*\(""", re.I),
         "HIGH"),
        ("jQuery.html()",
         re.compile(r"""\$\([^)]*\)\s*\.\s*html\s*\((?!\s*\))""", re.I),
         "MEDIUM"),
        ("jQuery.append()",
         re.compile(r"""\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\(""", re.I),
         "MEDIUM"),
    ],
    "script_execution": [
        ("eval",
         re.compile(r"""\beval\s*\("""),
         "HIGH"),
        ("Function()",
         re.compile(r"""\bnew\s+Function\s*\("""),
         "HIGH"),
        ("setTimeout(string)",
         re.compile(r"""\bsetTimeout\s*\(\s*['"`]"""),
         "HIGH"),
        ("setInterval(string)",
         re.compile(r"""\bsetInterval\s*\(\s*['"`]"""),
         "HIGH"),
        ("setTimeout(var)",
         re.compile(r"""\bsetTimeout\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]"""),
         "MEDIUM"),
        ("setInterval(var)",
         re.compile(r"""\bsetInterval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]"""),
         "MEDIUM"),
    ],
    "url_sink": [
        ("location.href",
         re.compile(r"""\blocation\s*\.href\s*="""),
         "MEDIUM"),
        ("location.assign",
         re.compile(r"""\blocation\s*\.\s*assign\s*\("""),
         "MEDIUM"),
        ("location.replace",
         re.compile(r"""\blocation\s*\.\s*replace\s*\("""),
         "MEDIUM"),
        ("window.open",
         re.compile(r"""\bwindow\s*\.\s*open\s*\("""),
         "MEDIUM"),
        ("document.location",
         re.compile(r"""\bdocument\s*\.\s*location\s*="""),
         "MEDIUM"),
    ],
    "storage_sink": [
        ("postMessage",
         re.compile(r"""\.postMessage\s*\("""),
         "MEDIUM"),
        ("localStorage.setItem",
         re.compile(r"""\blocalStorage\s*\.\s*setItem\s*\("""),
         "LOW"),
        ("document.cookie",
         re.compile(r"""\bdocument\s*\.\s*cookie\s*="""),
         "MEDIUM"),
    ],
}

# User-controllable taint sources — if one of these flows into a sink,
# the sink is more likely exploitable.
TAINT_SOURCES: Dict[str, re.Pattern] = {
    "location.search":    re.compile(r"""\blocation\s*\.\s*search"""),
    "location.hash":      re.compile(r"""\blocation\s*\.\s*hash"""),
    "location.href":      re.compile(r"""\blocation\s*\.\s*href"""),
    "document.referrer":  re.compile(r"""\bdocument\s*\.\s*referrer"""),
    "document.URL":       re.compile(r"""\bdocument\s*\.\s*URL"""),
    "document.documentURI": re.compile(r"""\bdocument\s*\.\s*documentURI"""),
    "window.name":        re.compile(r"""\bwindow\s*\.\s*name"""),
    "URLSearchParams":    re.compile(r"""\bnew\s+URLSearchParams"""),
    "postMessage.data":   re.compile(r"""(?:event|e|evt)\s*\.\s*data"""),
    "FormData":           re.compile(r"""\bnew\s+FormData"""),
}

PROTOTYPE_POLLUTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"""__proto__"""),
    re.compile(r"""constructor\s*\.\s*prototype"""),
    re.compile(r"""Object\s*\.\s*assign\s*\(\s*\{\}"""),
    re.compile(r"""\.constructor\s*\["""),
]

DANGEROUS_EVENT_HANDLERS = [
    "onclick", "onload", "onerror", "onmouseover", "onfocus",
    "onblur", "onsubmit", "onchange", "oninput", "onkeyup",
    "onkeydown", "onkeypress", "onmouseout", "onmouseenter",
]


class DOMAnalyzer:
    """
    Analyzes rendered DOM and JavaScript for client-side vulnerability sinks.

    Usage::

        analyzer = DOMAnalyzer()
        result = analyzer.analyze(
            url="https://example.com",
            rendered_html="<html>...</html>",
            js_sources=["inline:var x = location.hash; el.innerHTML = x;"],
        )
        print(result.sinks)
    """

    def analyze(
        self,
        url: str,
        rendered_html: str,
        js_sources: Optional[List[str]] = None,
    ) -> DOMAnalysisResult:
        """
        Run full DOM analysis on a page.

        Args:
            url: The page URL
            rendered_html: Full rendered HTML (after JS execution)
            js_sources: List of script contents / URLs from BrowserCrawler
        """
        result = DOMAnalysisResult(url=url)
        js_sources = js_sources or []

        # ── Collect all JavaScript to analyze ───────────────────────────
        scripts: List[Tuple[str, str]] = []  # (source_label, code)

        # Extract inline scripts from HTML
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>",
            rendered_html,
            re.DOTALL | re.I,
        )
        for i, code in enumerate(inline_scripts):
            if code.strip():
                scripts.append((f"inline_script_{i}", code))
                result.total_inline_scripts += 1

        # Process js_sources from BrowserCrawler
        for src in js_sources:
            if src.startswith("inline:"):
                scripts.append(("browser_inline", src[7:]))
                result.total_inline_scripts += 1
            else:
                result.total_external_scripts += 1
                # We don't have the content of external scripts here,
                # but we track them for reporting

        result.total_scripts_analyzed = len(scripts)

        # ── Scan each script for sinks ──────────────────────────────────
        for source_label, code in scripts:
            self._scan_code(code, source_label, result)

        # ── Scan HTML for dangerous event handlers ──────────────────────
        self._scan_event_handlers(rendered_html, result)

        # ── Check for postMessage listeners ─────────────────────────────
        result.postmessage_listeners = len(re.findall(
            r"""addEventListener\s*\(\s*['"]message['"]""",
            rendered_html,
        ))

        # ── Check for prototype pollution ───────────────────────────────
        full_js = "\n".join(code for _, code in scripts)
        for pattern in PROTOTYPE_POLLUTION_PATTERNS:
            result.prototype_pollution_indicators += len(pattern.findall(full_js))

        logger.info(
            "[DOM] %s | sinks=%d (high=%d, exploitable=%d) scripts=%d "
            "event_handlers=%d postmessage=%d proto_pollution=%d",
            url, len(result.sinks), result.high_severity_count,
            result.exploitable_count, result.total_scripts_analyzed,
            len(result.dangerous_event_handlers),
            result.postmessage_listeners,
            result.prototype_pollution_indicators,
        )

        return result

    # ── Internal scanning ─────────────────────────────────────────────────

    def _scan_code(self, code: str, source_label: str, result: DOMAnalysisResult):
        """Scan a block of JavaScript for dangerous sinks."""
        lines = code.split("\n")

        # Identify which taint sources appear in this code block
        taint_sources_present: List[str] = []
        for source_name, pattern in TAINT_SOURCES.items():
            if pattern.search(code):
                taint_sources_present.append(source_name)

        # Scan for sinks
        for category, patterns in SINK_PATTERNS.items():
            for sink_name, pattern, severity in patterns:
                for match in pattern.finditer(code):
                    line_num = code[:match.start()].count("\n") + 1

                    # Extract code context (surrounding line)
                    start_idx = max(0, match.start() - 60)
                    end_idx = min(len(code), match.end() + 60)
                    snippet = code[start_idx:end_idx].strip()

                    # Check if any taint source appears near this sink
                    # (within ~300 chars = rough same-function heuristic)
                    nearby_start = max(0, match.start() - 300)
                    nearby_end = min(len(code), match.end() + 300)
                    nearby_code = code[nearby_start:nearby_end]

                    tainted = ""
                    exploitable = False
                    for ts in taint_sources_present:
                        ts_pattern = TAINT_SOURCES[ts]
                        if ts_pattern.search(nearby_code):
                            tainted = ts
                            exploitable = True
                            break

                    # Boost confidence if source → sink path found
                    confidence = 0.4
                    if exploitable:
                        confidence = 0.85
                        severity = "HIGH"  # Upgrade if exploitable
                    elif taint_sources_present:
                        confidence = 0.6  # sources exist in same file

                    sink = DOMSink(
                        sink_type=sink_name,
                        category=category,
                        severity=severity,
                        code_snippet=snippet,
                        line_number=line_num,
                        source_url=source_label,
                        tainted_source=tainted,
                        exploitable=exploitable,
                        confidence=confidence,
                    )
                    result.sinks.append(sink)

    def _scan_event_handlers(self, html: str, result: DOMAnalysisResult):
        """Detect inline event handlers in HTML attributes."""
        for handler in DANGEROUS_EVENT_HANDLERS:
            pattern = re.compile(
                rf"""<[a-z][^>]*\s{handler}\s*=\s*['"]([^'"]+)['"]""",
                re.I,
            )
            for match in pattern.finditer(html):
                handler_code = match.group(1)
                result.dangerous_event_handlers.append({
                    "handler": handler,
                    "code": handler_code[:200],
                    "context": match.group(0)[:200],
                })

    # ── Convenience ───────────────────────────────────────────────────────

    @staticmethod
    def get_summary(results: List[DOMAnalysisResult]) -> Dict[str, Any]:
        """Aggregate summary across multiple pages."""
        total_sinks = sum(len(r.sinks) for r in results)
        total_exploitable = sum(r.exploitable_count for r in results)
        total_high = sum(r.high_severity_count for r in results)

        return {
            "pages_analyzed": len(results),
            "total_sinks": total_sinks,
            "total_exploitable": total_exploitable,
            "total_high_severity": total_high,
            "total_postmessage_listeners": sum(r.postmessage_listeners for r in results),
            "total_prototype_pollution": sum(r.prototype_pollution_indicators for r in results),
            "by_category": _count_by_key(results, "category"),
            "by_sink_type": _count_by_key(results, "sink_type"),
        }


def _count_by_key(results: List[DOMAnalysisResult], key: str) -> Dict[str, int]:
    """Count sinks grouped by a given attribute."""
    counts: Dict[str, int] = {}
    for r in results:
        for s in r.sinks:
            val = getattr(s, key, "unknown")
            counts[val] = counts.get(val, 0) + 1
    return counts
