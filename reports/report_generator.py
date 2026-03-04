"""
Aegis AI — Report Generation Agent
Generates professional security reports in PDF, JSON, and Markdown formats.
Each report includes vulnerability details, severity ratings, evidence, and remediation.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import asdict

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from agents.exploit_agent import VulnerabilityFinding
from utils.logger import get_logger

logger = get_logger(__name__, "REPORT")

REPORTS_DIR = Path(__file__).parent.parent / "reports" / "output"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ReportData:
    """Container for all report data."""

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        findings: List[VulnerabilityFinding],
        endpoints_count: int,
        technologies: List[str],
        scan_duration_seconds: float,
        agent_reasoning: List[str] = None,
        attack_graph: Dict = None,
        dedup_stats: Dict = None,
        fp_filter_stats: Dict = None,
        verification_stats: Dict = None,
        exploit_simulations: List[Dict] = None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 5)
        )
        self.endpoints_count = endpoints_count
        self.technologies = technologies
        self.scan_duration_seconds = scan_duration_seconds
        self.agent_reasoning = agent_reasoning or []
        self.attack_graph = attack_graph or {}
        self.dedup_stats = dedup_stats or {}
        self.fp_filter_stats = fp_filter_stats or {}
        self.verification_stats = verification_stats or {}
        self.exploit_simulations = exploit_simulations or []
        self.generated_at = datetime.utcnow()

        # Compute severity counts
        self.critical = sum(1 for f in findings if f.severity == "CRITICAL")
        self.high = sum(1 for f in findings if f.severity == "HIGH")
        self.medium = sum(1 for f in findings if f.severity == "MEDIUM")
        self.low = sum(1 for f in findings if f.severity == "LOW")

    @property
    def confirmed_findings(self) -> List[VulnerabilityFinding]:
        return [f for f in self.findings if getattr(f, "verified", False)]

    @property
    def unconfirmed_findings(self) -> List[VulnerabilityFinding]:
        return [f for f in self.findings if not getattr(f, "verified", False)]

    @property
    def top5(self) -> List[VulnerabilityFinding]:
        return self.findings[:5]

    @property
    def risk_rating(self) -> str:
        if self.critical > 0:
            return "CRITICAL"
        elif self.high > 0:
            return "HIGH"
        elif self.medium > 0:
            return "MEDIUM"
        elif self.low > 0:
            return "LOW"
        return "INFORMATIONAL"

    @property
    def executive_summary(self) -> str:
        vuln_total = len(self.findings)
        if vuln_total == 0:
            return (
                f"Security assessment of {self.target_url} completed. "
                f"No significant vulnerabilities were identified during this scan. "
                f"The application appears to follow security best practices based on automated testing. "
                f"Manual review is still recommended."
            )

        severity_str = []
        if self.critical:
            severity_str.append(f"{self.critical} critical")
        if self.high:
            severity_str.append(f"{self.high} high")
        if self.medium:
            severity_str.append(f"{self.medium} medium")
        if self.low:
            severity_str.append(f"{self.low} low")

        return (
            f"Security assessment of {self.target_url} identified {vuln_total} "
            f"potential vulnerabilities: {', '.join(severity_str)}. "
            f"The overall risk rating is {self.risk_rating}. "
            f"Immediate attention is required for critical and high severity findings. "
            f"Remediation guidance is provided for each vulnerability."
        )


class MarkdownReportGenerator:
    """Generates professional Markdown security reports."""

    def generate(self, data: ReportData) -> str:
        """Generate a complete Markdown report."""
        lines = []

        # Header
        lines.extend([
            f"# 🛡️ Aegis AI Security Report",
            f"",
            f"**Target:** {data.target_url}  ",
            f"**Scan ID:** `{data.scan_id}`  ",
            f"**Generated:** {data.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Risk Rating:** {'🔴' if data.risk_rating in ('CRITICAL', 'HIGH') else '🟡' if data.risk_rating == 'MEDIUM' else '🟢'} **{data.risk_rating}**",
            f"",
            f"---",
            f"",
            f"> ⚠️ **DISCLAIMER:** This report was generated by Aegis AI for authorized security testing only.",
            f"> Unauthorized use of this tool or its findings is illegal and unethical.",
            f"",
        ])

        # ── 1. Executive Summary ──────────────────────────────────────────
        lines.extend([
            f"## 1. Executive Summary",
            f"",
            data.executive_summary,
            f"",
        ])

        # Dedup stats callout
        ds = data.dedup_stats
        if ds:
            lines.extend([
                f"> **Deduplication:** {ds.get('raw_count', '?')} raw findings "
                f"→ {ds.get('deduplicated_count', '?')} unique vulnerabilities "
                f"({ds.get('false_positives_removed', 0)} false positives removed, "
                f"{ds.get('reduction_pct', 0):.0f}% reduction).",
                f"",
            ])

        # Verification stats callout
        vs = data.verification_stats
        if vs and vs.get("total", 0) > 0:
            lines.extend([
                f"> **Verification:** {vs.get('verified', 0)} verified, "
                f"{vs.get('rejected', 0)} rejected out of {vs.get('total', 0)} findings.",
                f"",
            ])

        # FP filter stats callout
        fps = data.fp_filter_stats
        if fps:
            lines.extend([
                f"> **False Positive Filter:** {fps.get('confirmed', 0)} confirmed, "
                f"{fps.get('suspicious', 0)} suspicious, "
                f"{fps.get('informational', 0)} informational, "
                f"{fps.get('suppressed', 0)} suppressed.",
                f"",
            ])

        # Statistics table
        confirmed = len(data.confirmed_findings)
        unconfirmed = len(data.unconfirmed_findings)
        lines.extend([
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Endpoints Discovered | {data.endpoints_count} |",
            f"| Unique Vulnerabilities | {len(data.findings)} |",
            f"| Confirmed (Verified) | {confirmed} |",
            f"| Unconfirmed | {unconfirmed} |",
            f"| Critical | {data.critical} |",
            f"| High | {data.high} |",
            f"| Medium | {data.medium} |",
            f"| Low | {data.low} |",
            f"| Technologies Detected | {', '.join(data.technologies) or 'None'} |",
            f"| Scan Duration | {data.scan_duration_seconds:.1f}s |",
            f"",
        ])

        # ── 2. Top 5 Risks ────────────────────────────────────────────────
        if data.top5:
            lines.extend([
                f"## 2. Top 5 Risks",
                f"",
                f"| # | Severity | Type | Endpoint | Confidence | Verified |",
                f"|---|----------|------|----------|------------|----------|",
            ])
            for idx, v in enumerate(data.top5, 1):
                verified_badge = "✅" if getattr(v, 'verified', False) else "❓"
                lines.append(
                    f"| {idx} | {v.severity} | {v.vuln_type.replace('_',' ').title()} "
                    f"| `{v.url[:60]}` | {v.confidence:.0%} | {verified_badge} |"
                )
            lines.append("")

        # ── 3. Confirmed Vulnerabilities ──────────────────────────────────
        if data.confirmed_findings:
            lines.extend([
                f"## 3. Confirmed Vulnerabilities",
                f"",
                f"*These findings have been verified with concrete proof.*",
                f"",
            ])
            self._render_findings(lines, data.confirmed_findings)

        # ── 4. Unconfirmed Findings ───────────────────────────────────────
        if data.unconfirmed_findings:
            section_num = 4 if data.confirmed_findings else 3
            lines.extend([
                f"## {section_num}. Unconfirmed Findings",
                f"",
                f"*These findings require manual verification.*",
                f"",
            ])
            self._render_findings(lines, data.unconfirmed_findings)

        # ── Exploit Simulation Scenarios ──────────────────────────────────
        if data.exploit_simulations:
            sim_section = 5 if data.confirmed_findings else 4
            lines.extend([
                f"## {sim_section}. Exploit Simulation Scenarios",
                f"",
                f"*The following multi-step attack scenarios were simulated based on confirmed vulnerabilities.*",
                f"",
            ])
            for sim in data.exploit_simulations:
                sev_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡"}.get(sim.get("severity", ""), "⚪")
                lines.extend([
                    f"### {sev_emoji} {sim['name']}",
                    f"",
                    f"**Severity:** {sim['severity']} | **Impact:** {sim['impact']}",
                    f"",
                    f"**Vulnerabilities leveraged:** {', '.join(sim.get('vulnerabilities_used', []))}",
                    f"",
                    f"**Attack steps:**",
                    f"",
                ])
                for i, step in enumerate(sim.get("steps", []), 1):
                    lines.append(f"{i}. {step}")
                lines.extend([
                    f"",
                    f"**Affected endpoints:** {', '.join(sim.get('affected_urls', [])[:3]) or 'N/A'}",
                    f"",
                    f"---",
                    f"",
                ])

        # ── Remediation Roadmap ───────────────────────────────────────────
        if data.findings:
            lines.extend([
                f"## Remediation Roadmap",
                f"",
                f"| Priority | Vulnerability | Action |",
                f"|----------|---------------|--------|",
            ])
            for idx, v in enumerate(data.findings, 1):
                rem = v.remediation
                lines.append(
                    f"| {idx} | {v.title} | {rem[:80]}{'…' if len(rem) > 80 else ''} |"
                )
            lines.append("")

        # Agent Reasoning Log
        if data.agent_reasoning:
            lines.extend([
                f"## Agent Reasoning Log",
                f"",
                f"*The following shows the AI agent's reasoning process during the scan.*",
                f"",
            ])
            for thought in data.agent_reasoning:
                lines.append(f"- {thought}")
            lines.append("")

        # Methodology
        lines.extend([
            f"## Methodology",
            f"",
            f"This assessment was conducted using Aegis AI's automated multi-agent pipeline:",
            f"",
            f"1. **Reconnaissance** — Crawled the target to discover all reachable endpoints",
            f"2. **Endpoint Intelligence** — Classified endpoints by type and risk level",
            f"3. **Strategy Planning** — Selected optimal test payloads per endpoint category",
            f"4. **Vulnerability Testing** — Smart payload engine with context-aware classification",
            f"5. **Deduplication & Filtering** — Merged duplicates, removed false positives",
            f"6. **Multi-Stage Verification** — SQLi/XSS/Redirect verification with differential analysis",
            f"7. **False Positive Suppression** — Signal-weighted scoring (reflection, errors, diff, exploit confirmation)",
            f"8. **ML Classification** — Random Forest classifier + Isolation Forest anomaly detection",
            f"9. **Attack Graph & Chain Analysis** — NetworkX-based multi-step attack discovery",
            f"10. **Risk Scoring** — Composite scoring (CVSS × 0.40 + confidence × 0.25 + severity × 0.15)",
            f"11. **Exploit Simulation** — Multi-step attack chain narrative generation",
            f"12. **Report Generation** — Compiled findings with evidence and remediation",
            f"",
            f"## Disclaimer",
            f"",
            f"This report was generated by Aegis AI for **authorized security testing only**.",
            f"The tool and its findings must only be used on systems you own or have explicit",
            f"written permission to test. Unauthorized scanning is illegal under computer fraud laws.",
            f"",
        ])

        return "\n".join(lines)

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _render_findings(lines: list, findings: List[VulnerabilityFinding]):
        """Render a list of vulnerability findings in Markdown."""
        for i, vuln in enumerate(findings, 1):
            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "INFO": "ℹ️",
            }.get(vuln.severity, "⚪")

            verified_tag = " ✅ VERIFIED" if getattr(vuln, 'verified', False) else ""

            lines.extend([
                f"### {i}. {severity_emoji} {vuln.title}{verified_tag}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Severity** | {vuln.severity} |",
                f"| **Type** | {vuln.vuln_type.replace('_', ' ').title()} |",
                f"| **URL** | `{vuln.url}` |",
                f"| **Parameter** | `{vuln.parameter or 'N/A'}` |",
                f"| **CWE** | {vuln.cwe_id or 'N/A'} |",
                f"| **Confidence** | {vuln.confidence:.0%} |",
                f"| **ML Prediction** | {vuln.ml_prediction} |",
                f"",
                f"**Description**",
                f"",
                f"{vuln.description}",
                f"",
            ])

            if vuln.payload:
                lines.extend([
                    f"**Payload Used**",
                    f"",
                    f"```",
                    vuln.payload,
                    f"```",
                    f"",
                ])

            if vuln.evidence:
                lines.extend([
                    f"**Evidence**",
                    f"",
                    f"> {vuln.evidence}",
                    f"",
                ])

            # Request / response proof (Step 8)
            req_ev = getattr(vuln, "request_evidence", "")
            resp_ev = getattr(vuln, "response_evidence", "")
            if req_ev:
                lines.extend([
                    f"<details><summary><b>Request Evidence</b></summary>",
                    f"",
                    f"```http",
                    req_ev,
                    f"```",
                    f"</details>",
                    f"",
                ])
            if resp_ev:
                lines.extend([
                    f"<details><summary><b>Response Evidence</b></summary>",
                    f"",
                    f"```http",
                    resp_ev,
                    f"```",
                    f"</details>",
                    f"",
                ])

            lines.extend([
                f"**Impact**",
                f"",
                f"{vuln.impact}",
                f"",
                f"**Remediation**",
                f"",
                f"{vuln.remediation}",
                f"",
                f"---",
                f"",
            ])


class JSONReportGenerator:
    """Generates machine-readable JSON reports."""

    def generate(self, data: ReportData) -> Dict:
        """Generate complete JSON report structure."""
        return {
            "aegis_report": {
                "version": "1.0",
                "scan_id": data.scan_id,
                "generated_at": data.generated_at.isoformat(),
                "target": {
                    "url": data.target_url,
                    "technologies": data.technologies,
                    "endpoints_count": data.endpoints_count,
                },
                "summary": {
                    "risk_rating": data.risk_rating,
                    "total_vulnerabilities": len(data.findings),
                    "critical": data.critical,
                    "high": data.high,
                    "medium": data.medium,
                    "low": data.low,
                    "scan_duration_seconds": data.scan_duration_seconds,
                    "executive_summary": data.executive_summary,
                },
                "vulnerabilities": [
                    {
                        "id": i + 1,
                        "type": f.vuln_type,
                        "title": f.title,
                        "severity": f.severity,
                        "url": f.url,
                        "parameter": f.parameter,
                        "payload": f.payload,
                        "http_method": f.http_method,
                        "confidence": f.confidence,
                        "verified": getattr(f, "verified", False),
                        "evidence": f.evidence,
                        "request_evidence": getattr(f, "request_evidence", ""),
                        "response_evidence": getattr(f, "response_evidence", ""),
                        "description": f.description,
                        "impact": f.impact,
                        "remediation": f.remediation,
                        "cwe_id": f.cwe_id,
                        "ml_prediction": f.ml_prediction,
                        "ml_confidence": f.ml_confidence,
                        "anomaly_score": f.anomaly_score,
                    }
                    for i, f in enumerate(data.findings)
                ],
                "dedup_stats": data.dedup_stats,
                "verification_stats": data.verification_stats,
                "fp_filter_stats": data.fp_filter_stats,
                "exploit_simulations": data.exploit_simulations,
                "agent_reasoning": data.agent_reasoning,
                "attack_graph": data.attack_graph,
                "disclaimer": (
                    "Generated by Aegis AI for authorized security testing only. "
                    "Unauthorized use is illegal."
                ),
            }
        }


class PDFReportGenerator:
    """Generates professional PDF security reports using ReportLab."""

    def generate(self, data: ReportData, output_path: Path) -> Optional[Path]:
        """Generate PDF report. Returns path if successful."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import (
                HexColor, black, white, grey, red, orange, green
            )
            from reportlab.lib.units import inch, cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, HRFlowable, PageBreak
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        except ImportError:
            logger.warning("ReportLab not installed — PDF report skipped")
            return None

        # Color palette
        DARK_BG = HexColor("#0f172a")
        ACCENT = HexColor("#4f46e5")
        CRITICAL_COLOR = HexColor("#7f1d1d")
        HIGH_COLOR = HexColor("#ef4444")
        MEDIUM_COLOR = HexColor("#f59e0b")
        LOW_COLOR = HexColor("#10b981")
        TEXT_LIGHT = HexColor("#e2e8f0")
        TEXT_GRAY = HexColor("#94a3b8")

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            leftMargin=1.0 * inch,
            rightMargin=1.0 * inch,
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            "Title", parent=styles["Title"],
            fontSize=24, textColor=ACCENT,
            spaceAfter=6, fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "Heading", parent=styles["Heading2"],
            fontSize=14, textColor=ACCENT,
            spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "Body", parent=styles["Normal"],
            fontSize=10, spaceAfter=6, leading=14,
        )
        code_style = ParagraphStyle(
            "Code", parent=styles["Code"],
            fontSize=9, fontName="Courier",
            backColor=HexColor("#1e293b"), textColor=HexColor("#e2e8f0"),
            leftIndent=12, rightIndent=12, spaceBefore=4, spaceAfter=4,
        )

        def severity_color(sev: str):
            return {
                "CRITICAL": CRITICAL_COLOR,
                "HIGH": HIGH_COLOR,
                "MEDIUM": MEDIUM_COLOR,
                "LOW": LOW_COLOR,
            }.get(sev, grey)

        # ── Title Page ───────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("🛡️ AEGIS AI", title_style))
        story.append(Paragraph("Security Assessment Report", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 0.25 * inch))

        # Metadata table
        meta_data = [
            ["Target URL", data.target_url],
            ["Scan ID", data.scan_id],
            ["Generated", data.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Overall Risk", data.risk_rating],
            ["Duration", f"{data.scan_duration_seconds:.1f} seconds"],
        ]
        meta_table = Table(meta_data, colWidths=[2 * inch, 4.5 * inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (0, -1), TEXT_LIGHT),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#334155")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.25 * inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(data.executive_summary, body_style))

        # Dedup stats
        ds = data.dedup_stats
        if ds:
            story.append(Paragraph(
                f"<b>Deduplication:</b> {ds.get('raw_count','?')} raw findings → "
                f"{ds.get('deduplicated_count','?')} unique "
                f"({ds.get('false_positives_removed',0)} false positives removed, "
                f"{ds.get('reduction_pct',0):.0f}% reduction)",
                body_style,
            ))

        story.append(Spacer(1, 0.2 * inch))

        # Severity breakdown chart (table-based)
        story.append(Paragraph("Vulnerability Summary", heading_style))
        confirmed_count = len(data.confirmed_findings)
        unconfirmed_count = len(data.unconfirmed_findings)
        sev_data = [
            ["Severity", "Count", "Status"],
            ["CRITICAL", str(data.critical), "Immediate Action Required"],
            ["HIGH", str(data.high), "Action Required"],
            ["MEDIUM", str(data.medium), "Review Recommended"],
            ["LOW", str(data.low), "Address When Possible"],
            ["Confirmed", str(confirmed_count), "Verified with evidence"],
            ["Unconfirmed", str(unconfirmed_count), "Manual review needed"],
        ]
        sev_table = Table(sev_data, colWidths=[1.5 * inch, 1 * inch, 4 * inch])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, grey),
            ("BACKGROUND", (0, 1), (0, 1), CRITICAL_COLOR),
            ("TEXTCOLOR", (0, 1), (0, 1), white),
            ("BACKGROUND", (0, 2), (0, 2), HIGH_COLOR),
            ("TEXTCOLOR", (0, 2), (0, 2), white),
            ("BACKGROUND", (0, 3), (0, 3), MEDIUM_COLOR),
            ("BACKGROUND", (0, 4), (0, 4), LOW_COLOR),
            ("TEXTCOLOR", (0, 4), (0, 4), white),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (1, 1), (-1, -1), [white, HexColor("#f8fafc")]),
        ]))
        story.append(sev_table)

        # ── Vulnerability Details ────────────────────────────────────────────
        if data.findings:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Findings", title_style))
            story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))

            for i, vuln in enumerate(data.findings, 1):
                story.append(Spacer(1, 0.2 * inch))
                sev_col = severity_color(vuln.severity)

                # Vulnerability header
                verified_str = " [VERIFIED]" if getattr(vuln, 'verified', False) else ""
                vuln_title_style = ParagraphStyle(
                    f"VT{i}", parent=heading_style,
                    textColor=sev_col,
                )
                story.append(Paragraph(f"{i}. {vuln.title}{verified_str}", vuln_title_style))

                # Details table
                detail_data = [
                    ["Severity", vuln.severity, "CWE", vuln.cwe_id or "N/A"],
                    ["URL", vuln.url[:60], "Method", vuln.http_method],
                    ["Parameter", vuln.parameter or "N/A", "Confidence", f"{vuln.confidence:.0%}"],
                    ["Verified", "Yes" if getattr(vuln, 'verified', False) else "No", "ML", vuln.ml_prediction],
                ]
                det_table = Table(detail_data, colWidths=[1.2*inch, 2.5*inch, 1.2*inch, 1.6*inch])
                det_table.setStyle(TableStyle([
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, grey),
                    ("BACKGROUND", (0, 0), (0, 0), sev_col),
                    ("TEXTCOLOR", (0, 0), (0, 0), white),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, HexColor("#f8fafc")]),
                ]))
                story.append(det_table)
                story.append(Spacer(1, 0.1 * inch))

                # Description, Impact, Remediation
                for section, content in [
                    ("Description", vuln.description),
                    ("Impact", vuln.impact),
                    ("Remediation", vuln.remediation),
                ]:
                    sec_style = ParagraphStyle(
                        f"Sec_{section}_{i}", parent=body_style,
                        fontName="Helvetica-Bold", textColor=ACCENT,
                    )
                    story.append(Paragraph(section, sec_style))
                    story.append(Paragraph(content, body_style))

                if vuln.payload:
                    story.append(Paragraph("Payload", ParagraphStyle(
                        f"PL_{i}", parent=body_style,
                        fontName="Helvetica-Bold", textColor=ACCENT,
                    )))
                    story.append(Paragraph(
                        f"<font name='Courier' size='9'>{vuln.payload[:200]}</font>",
                        ParagraphStyle(f"PLCode_{i}", parent=body_style,
                                       backColor=HexColor("#1e293b"),
                                       textColor=HexColor("#e2e8f0"),
                                       leftIndent=8, rightIndent=8,
                                       spaceBefore=2, spaceAfter=6)
                    ))

                story.append(HRFlowable(
                    width="100%", thickness=0.5, color=HexColor("#334155")
                ))

        # Disclaimer
        story.append(PageBreak())
        story.append(Paragraph("Disclaimer", heading_style))
        story.append(Paragraph(
            "This report was generated by Aegis AI for AUTHORIZED security testing only. "
            "The tool and its findings must only be used on systems you own or have "
            "explicit written permission to test. Unauthorized scanning is illegal under "
            "computer fraud and abuse laws. The authors assume no liability for misuse.",
            body_style
        ))

        doc.build(story)
        logger.info(f"PDF report generated: {output_path}")
        return output_path


class ReportAgent:
    """
    Report Generation Agent — orchestrates all report formats.

    Produces PDF, JSON, and Markdown reports for each scan.
    """

    def __init__(self, on_event=None):
        self.on_event = on_event
        self.md_gen = MarkdownReportGenerator()
        self.json_gen = JSONReportGenerator()
        self.pdf_gen = PDFReportGenerator()

    async def generate(self, data: ReportData) -> Dict[str, Optional[str]]:
        """Generate all report formats and return file paths."""
        logger.info(f"Generating reports for scan {data.scan_id}")

        output_paths = {}
        base_name = f"aegis_report_{data.scan_id}"

        # Markdown Report
        try:
            md_content = self.md_gen.generate(data)
            md_path = REPORTS_DIR / f"{base_name}.md"
            md_path.write_text(md_content, encoding="utf-8")
            output_paths["markdown"] = str(md_path)
            logger.info(f"Markdown report: {md_path}")
        except Exception as e:
            logger.error(f"Markdown report failed: {e}")
            output_paths["markdown"] = None

        # JSON Report
        try:
            json_data = self.json_gen.generate(data)
            json_path = REPORTS_DIR / f"{base_name}.json"
            json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
            output_paths["json"] = str(json_path)
            logger.info(f"JSON report: {json_path}")
        except Exception as e:
            logger.error(f"JSON report failed: {e}")
            output_paths["json"] = None

        # PDF Report
        try:
            pdf_path = REPORTS_DIR / f"{base_name}.pdf"
            result = self.pdf_gen.generate(data, pdf_path)
            output_paths["pdf"] = str(result) if result else None
        except Exception as e:
            logger.error(f"PDF report failed: {e}")
            output_paths["pdf"] = None

        if self.on_event:
            await self.on_event({
                "agent": "REPORT",
                "event_type": "COMPLETE",
                "message": f"Reports generated: {', '.join(k for k, v in output_paths.items() if v)}",
                "details": output_paths,
            })

        return output_paths
