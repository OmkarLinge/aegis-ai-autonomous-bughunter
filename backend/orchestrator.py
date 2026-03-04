"""
Aegis AI — Scan Orchestrator
Coordinates all agents in sequence, manages scan lifecycle,
broadcasts real-time events via WebSocket, and persists results.
"""
import asyncio
import uuid
import time
import json
from typing import List, Dict, Optional, Callable, Set
from datetime import datetime

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from agents.recon_agent import ReconAgent, ReconResult
from agents.endpoint_intelligence_agent import EndpointIntelligenceAgent, ClassifiedEndpoint
from agents.exploit_agent import ExploitAgent, VulnerabilityFinding
from agents.strategy_agent import StrategyAgent
from reports.report_generator import ReportAgent, ReportData
from backend.analysis.attack_graph import AttackGraph
from backend.analysis.risk_propagation import RiskPropagationEngine
from backend.analysis.attack_chain_engine import AttackChainEngine
from backend.analysis.risk_scoring_engine import RiskScoringEngine
from backend.analysis.deduplication_engine import DeduplicationEngine
from backend.security_intelligence.cve_engine import CVEEngine
from utils.logger import get_logger
from utils.config import config

logger = get_logger(__name__, "ORCHESTRATOR")


class ScanOrchestrator:
    """
    Master coordinator for all Aegis AI scanning agents.

    Execution flow:
    1. Validate target and authorization
    2. Recon Agent → discover attack surface
    3. Endpoint Intelligence Agent → classify endpoints
    4. Strategy Agent → plan scan strategy
    5. Exploit Agent → test vulnerabilities
    6. Report Agent → generate reports
    7. Persist results to database
    """

    def __init__(self, websocket_broadcaster: Optional[Callable] = None):
        self.broadcaster = websocket_broadcaster
        self._active_scans: Dict[str, Dict] = {}
        self._scan_tasks: Dict[str, asyncio.Task] = {}

    async def _broadcast(self, scan_id: str, event: Dict):
        """Broadcast event to connected WebSocket clients."""
        event["scan_id"] = scan_id
        event["timestamp"] = datetime.utcnow().isoformat()

        if self.broadcaster:
            try:
                await self.broadcaster(scan_id, event)
            except Exception as e:
                logger.debug(f"Broadcast error: {e}")

    async def start_scan(
        self,
        target_url: str,
        scan_depth: int = 3,
        scan_types: List[str] = None,
        authorized: bool = False,
        target_name: str = None,
    ) -> str:
        """
        Start a new scan job.

        Args:
            target_url: The target URL to scan
            scan_depth: How deep to crawl (1-5)
            scan_types: List of test types to run
            authorized: User confirms authorization
            target_name: Optional friendly name for the target

        Returns:
            scan_id: Unique identifier for this scan job
        """
        scan_id = str(uuid.uuid4())[:8].upper()

        if not authorized:
            logger.warning(f"[ORCHESTRATOR] Scan {scan_id} rejected — authorization not confirmed")
            raise ValueError(
                "Authorization required. You must confirm you have permission to scan this target."
            )

        scan_types = scan_types or ["sql_injection", "xss", "open_redirect", "security_headers"]

        logger.info(
            f"[ORCHESTRATOR] Starting scan {scan_id} | "
            f"target={target_url} depth={scan_depth}"
        )

        # Initialize scan state
        self._active_scans[scan_id] = {
            "scan_id": scan_id,
            "target_url": target_url,
            "target_name": target_name or target_url,
            "status": "pending",
            "started_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "progress": 0,
            "current_agent": None,
            "endpoints": [],
            "vulnerabilities": [],
            "technologies": [],
            "agent_logs": [],
            "reasoning": [],
            "attack_graph": {},
            "report_paths": {},
            "error": None,
        }

        # Start scan as background task
        task = asyncio.create_task(
            self._run_scan(scan_id, target_url, scan_depth, scan_types, authorized)
        )
        self._scan_tasks[scan_id] = task

        return scan_id

    async def _run_scan(
        self,
        scan_id: str,
        target_url: str,
        scan_depth: int,
        scan_types: List[str],
        authorized: bool,
    ):
        """Execute the full scan pipeline."""
        scan_start = time.monotonic()
        state = self._active_scans[scan_id]

        try:
            state["status"] = "running"
            await self._broadcast(scan_id, {
                "type": "scan_started",
                "message": f"Scan started for {target_url}",
                "agent": "ORCHESTRATOR",
            })

            def event_handler(event):
                """Synchronous wrapper for agent events."""
                return self._handle_agent_event(scan_id, event)

            async def async_event_handler(event):
                """Async event handler passed to agents."""
                state["agent_logs"].append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "agent": event.get("agent", "SYSTEM"),
                    "event_type": event.get("event_type", "INFO"),
                    "message": event.get("message", ""),
                    "details": event.get("details", {}),
                })
                await self._broadcast(scan_id, {
                    "type": "agent_event",
                    **event,
                })

            # ── Phase 1: Reconnaissance ─────────────────────────────────────
            state["current_agent"] = "RECON"
            state["progress"] = 10

            recon_agent = ReconAgent(
                target_url=target_url,
                authorized=authorized,
                max_depth=scan_depth,
                on_event=async_event_handler,
            )
            recon_result: ReconResult = await recon_agent.run()

            state["endpoints"] = [
                {
                    "url": ep.url,
                    "path": ep.path,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "response_time_ms": ep.response_time_ms,
                    "content_type": ep.content_type,
                    "endpoint_type": ep.endpoint_type or "unknown",
                    "parameters": ep.parameters,
                    "forms_count": len(ep.forms),
                    "technologies": ep.technologies,
                    "depth": ep.depth,
                }
                for ep in recon_result.endpoints
            ]
            state["technologies"] = recon_result.technologies
            state["reasoning"].extend(recon_result.agent_reasoning)
            state["progress"] = 30

            await self._broadcast(scan_id, {
                "type": "recon_complete",
                "agent": "RECON",
                "message": f"Recon complete: {len(recon_result.endpoints)} endpoints",
                "data": {
                    "endpoint_count": len(recon_result.endpoints),
                    "technologies": recon_result.technologies,
                },
            })

            # ── Phase 2: Endpoint Intelligence ─────────────────────────────
            state["current_agent"] = "ENDPOINT"
            state["progress"] = 40

            intel_agent = EndpointIntelligenceAgent(on_event=async_event_handler)
            classified = await intel_agent.analyze(recon_result.endpoints)

            # Update endpoints with classification data
            classified_map = {c.endpoint.path: c for c in classified}
            for ep in state["endpoints"]:
                if ep["path"] in classified_map:
                    c = classified_map[ep["path"]]
                    ep["endpoint_type"] = c.category
                    ep["risk_score"] = c.risk_score
                    ep["test_types"] = c.test_types

            # Generate attack graph
            attack_graph = intel_agent.generate_attack_graph(classified)
            state["attack_graph"] = attack_graph

            await self._broadcast(scan_id, {
                "type": "classification_complete",
                "agent": "ENDPOINT",
                "message": f"Classified {len(classified)} endpoints",
                "data": {"attack_graph": attack_graph},
            })

            # ── Phase 3: Strategy Planning ──────────────────────────────────
            state["current_agent"] = "STRATEGY"
            state["progress"] = 50

            strategy_agent = StrategyAgent(target_url)
            strategy = strategy_agent.plan_scan(classified)
            state["reasoning"].extend(strategy_agent.reasoning_log)

            await self._broadcast(scan_id, {
                "type": "strategy_planned",
                "agent": "STRATEGY",
                "message": f"Strategy: {strategy.risk_level} risk, ~{strategy.estimated_duration_seconds:.0f}s",
                "data": {
                    "risk_level": strategy.risk_level,
                    "test_count": len(strategy.test_sequence),
                    "reasoning": strategy_agent.reasoning_log[-3:],
                },
            })

            # ── Phase 4: Exploit Testing ────────────────────────────────────
            state["current_agent"] = "EXPLOIT"
            state["progress"] = 60

            exploit_agent = ExploitAgent(
                target_url=target_url,
                authorized=authorized,
                on_event=async_event_handler,
            )
            raw_findings: List[VulnerabilityFinding] = await exploit_agent.run_all(
                strategy.target_endpoints
            )

            # Adapt strategy based on findings
            if raw_findings:
                remaining = strategy_agent.adapt_strategy(raw_findings, classified)

            # ── Phase 4a: Deduplication & False-Positive Filtering ──────────
            state["current_agent"] = "DEDUP"
            await self._broadcast(scan_id, {
                "type": "agent_event",
                "agent": "DEDUP",
                "event_type": "DEDUP_START",
                "message": f"Deduplicating {len(raw_findings)} raw findings…",
            })

            dedup_engine = DeduplicationEngine()
            dedup_vulns = dedup_engine.process(
                [self._finding_to_dict(f) for f in raw_findings],
                attack_chains=[],  # chains not yet discovered at this point
            )
            dedup_stats = dedup_engine.get_stats()

            # Rebuild VulnerabilityFinding list from deduplicated results
            findings = self._rebuild_findings(dedup_vulns, raw_findings)

            state["raw_vulnerability_count"] = len(raw_findings)
            state["dedup_stats"] = dedup_stats

            logger.info(
                "[ORCHESTRATOR] Dedup: %d raw → %d unique (%d false positives removed, %.0f%% reduction)",
                dedup_stats["raw_count"],
                dedup_stats["deduplicated_count"],
                dedup_stats["false_positives_removed"],
                dedup_stats["reduction_pct"],
            )

            await self._broadcast(scan_id, {
                "type": "dedup_complete",
                "agent": "DEDUP",
                "message": (
                    f"Deduplicated: {dedup_stats['raw_count']} → "
                    f"{dedup_stats['deduplicated_count']} unique findings "
                    f"({dedup_stats['reduction_pct']:.0f}% reduction)"
                ),
                "data": dedup_stats,
            })

            # Build final attack graph with vulnerabilities (legacy)
            final_graph = strategy_agent.build_attack_graph(classified, findings)

            # ── Phase 4b: Attack Graph Engine (NetworkX) ────────────────
            state["current_agent"] = "ATTACK_GRAPH"
            await self._broadcast(scan_id, {
                "type": "agent_event",
                "agent": "ATTACK_GRAPH",
                "event_type": "BUILD_START",
                "message": "Building attack graph and computing risk propagation…",
            })

            attack_graph_engine = AttackGraph(target_url=target_url)
            attack_graph_engine.build_from_scan_results(
                endpoints=state["endpoints"],
                vulnerabilities=[
                    {
                        "vuln_type": f.vuln_type,
                        "title": f.title,
                        "severity": f.severity,
                        "url": f.url,
                        "parameter": f.parameter,
                        "confidence": f.confidence,
                    }
                    for f in findings
                ],
            )
            attack_graph_engine.compute_all_paths()

            # Risk propagation
            risk_engine = RiskPropagationEngine(attack_graph_engine.graph)
            risk_engine.propagate()

            graph_data = attack_graph_engine.to_dict()
            graph_data["risk_propagation"] = risk_engine.to_dict()
            # Merge legacy keys so existing frontend still works
            graph_data["nodes"] = graph_data.get("nodes", []) or final_graph.get("nodes", [])
            graph_data["edges"] = graph_data.get("edges", []) or final_graph.get("edges", [])
            state["attack_graph"] = graph_data

            await self._broadcast(scan_id, {
                "type": "attack_graph_ready",
                "agent": "ATTACK_GRAPH",
                "message": (
                    f"Attack graph built: {graph_data['node_count']} nodes, "
                    f"{graph_data['edge_count']} edges, "
                    f"{len(graph_data.get('paths', []))} attack paths"
                ),
                "data": {
                    "node_count": graph_data["node_count"],
                    "edge_count": graph_data["edge_count"],
                    "path_count": len(graph_data.get("paths", [])),
                    "risk_summary": graph_data.get("risk_summary", {}),
                },
            })

            # Store findings
            state["vulnerabilities"] = [
                {
                    "id": i + 1,
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "severity": f.severity,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "http_method": f.http_method,
                    "status_code": f.status_code,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "description": f.description,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "cwe_id": f.cwe_id,
                    "ml_prediction": f.ml_prediction,
                    "ml_confidence": f.ml_confidence,
                    "anomaly_score": f.anomaly_score,
                    "verified": getattr(f, "verified", False),
                    "request_evidence": getattr(f, "request_evidence", ""),
                    "response_evidence": getattr(f, "response_evidence", ""),
                }
                for i, f in enumerate(findings)
            ]

            # ── Phase 4c: CVE Intelligence Enrichment ───────────────────────
            cve_engine = CVEEngine()
            cve_engine.enrich_scan_results(state["vulnerabilities"])
            cve_stats = cve_engine.get_stats()
            logger.info(
                "CVE enrichment complete — %d matched, %d unmatched",
                cve_stats["matched"],
                cve_stats["unmatched"],
            )

            await self._broadcast(scan_id, {
                "type": "cve_enrichment_complete",
                "agent": "CVE_INTEL",
                "message": (
                    f"CVE intelligence: {cve_stats['matched']} vulnerabilities "
                    f"mapped to known CVEs"
                ),
                "data": cve_stats,
            })

            # ── Phase 4d: Attack Chain Discovery ────────────────────────────
            state["current_agent"] = "ATTACK_CHAIN"
            await self._broadcast(scan_id, {
                "type": "agent_event",
                "agent": "ATTACK_CHAIN",
                "event_type": "DISCOVERY_START",
                "message": "Discovering autonomous multi-step attack chains…",
            })

            # Build CVE intel lookup for the chain engine
            from backend.security_intelligence.cve_database import CVE_DATABASE
            chain_engine = AttackChainEngine(
                graph=attack_graph_engine.graph,
                cve_intel=CVE_DATABASE,
            )
            attack_chains = chain_engine.discover_attack_chains()
            chain_data = chain_engine.to_dict()
            chain_stats = chain_engine.get_stats()
            state["attack_chains"] = chain_data

            logger.info(
                "Attack chain discovery complete — %d chains (%d critical, %d high)",
                chain_stats["total_chains"],
                chain_stats["critical"],
                chain_stats["high"],
            )

            await self._broadcast(scan_id, {
                "type": "attack_chains_ready",
                "agent": "ATTACK_CHAIN",
                "message": (
                    f"Discovered {chain_stats['total_chains']} attack chains — "
                    f"{chain_stats['critical']} critical, {chain_stats['high']} high"
                ),
                "data": chain_stats,
            })

            # ── Phase 4e: Risk Scoring ──────────────────────────────────────
            state["current_agent"] = "RISK_SCORE"
            risk_engine = RiskScoringEngine()
            risk_result = risk_engine.compute(state)
            state["risk_score"] = risk_result

            logger.info(
                "Risk scoring complete — Score: %s/100 (%s)",
                risk_result["score"],
                risk_result["risk_level"],
            )

            await self._broadcast(scan_id, {
                "type": "risk_score_ready",
                "agent": "RISK_SCORE",
                "message": (
                    f"Security Score: {risk_result['score']}/100 — "
                    f"Risk Level: {risk_result['risk_level']}"
                ),
                "data": risk_result,
            })

            state["progress"] = 80

            severity_counts = {
                "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity == "HIGH"),
                "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity == "LOW"),
            }

            await self._broadcast(scan_id, {
                "type": "exploit_complete",
                "agent": "EXPLOIT",
                "message": f"Testing complete: {len(findings)} vulnerabilities found",
                "data": {"findings_count": len(findings), **severity_counts},
            })

            # ── Phase 5: Report Generation ──────────────────────────────────
            state["current_agent"] = "REPORT"
            state["progress"] = 90

            duration = time.monotonic() - scan_start
            report_data = ReportData(
                scan_id=scan_id,
                target_url=target_url,
                findings=findings,
                endpoints_count=len(recon_result.endpoints),
                technologies=recon_result.technologies,
                scan_duration_seconds=duration,
                agent_reasoning=state["reasoning"],
                attack_graph=final_graph,
                dedup_stats=dedup_stats,
            )

            report_agent = ReportAgent(on_event=async_event_handler)
            report_paths = await report_agent.generate(report_data)
            state["report_paths"] = report_paths

            # ── Complete ────────────────────────────────────────────────────
            state["status"] = "completed"
            state["progress"] = 100
            state["completed_at"] = datetime.utcnow().isoformat()
            state["duration_seconds"] = duration
            state["current_agent"] = None

            await self._broadcast(scan_id, {
                "type": "scan_complete",
                "agent": "ORCHESTRATOR",
                "message": f"Scan complete in {duration:.1f}s",
                "data": {
                    "duration": duration,
                    "endpoints": len(recon_result.endpoints),
                    "vulnerabilities": len(findings),
                    "report_paths": report_paths,
                    **severity_counts,
                },
            })

            logger.info(
                f"[ORCHESTRATOR] Scan {scan_id} COMPLETE | "
                f"endpoints={len(recon_result.endpoints)} "
                f"vulns={len(findings)} "
                f"time={duration:.1f}s"
            )

        except asyncio.CancelledError:
            state["status"] = "cancelled"
            state["completed_at"] = datetime.utcnow().isoformat()
            await self._broadcast(scan_id, {
                "type": "scan_cancelled",
                "agent": "ORCHESTRATOR",
                "message": "Scan was cancelled",
            })

        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Scan {scan_id} FAILED: {e}", exc_info=True)
            state["status"] = "failed"
            state["error"] = str(e)
            state["completed_at"] = datetime.utcnow().isoformat()
            await self._broadcast(scan_id, {
                "type": "scan_failed",
                "agent": "ORCHESTRATOR",
                "message": f"Scan failed: {str(e)}",
                "data": {"error": str(e)},
            })

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        task = self._scan_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def get_scan_state(self, scan_id: str) -> Optional[Dict]:
        """Get current state of a scan."""
        return self._active_scans.get(scan_id)

    def get_all_scans(self) -> List[Dict]:
        """Get list of all scans with summary info."""
        return [
            {
                "scan_id": s["scan_id"],
                "target_url": s["target_url"],
                "target_name": s.get("target_name", s["target_url"]),
                "status": s["status"],
                "started_at": s["started_at"],
                "completed_at": s.get("completed_at"),
                "progress": s.get("progress", 0),
                "vulnerability_count": len(s.get("vulnerabilities", [])),
                "endpoint_count": len(s.get("endpoints", [])),
                "severity_summary": {
                    "critical": sum(1 for v in s.get("vulnerabilities", []) if v["severity"] == "CRITICAL"),
                    "high": sum(1 for v in s.get("vulnerabilities", []) if v["severity"] == "HIGH"),
                    "medium": sum(1 for v in s.get("vulnerabilities", []) if v["severity"] == "MEDIUM"),
                    "low": sum(1 for v in s.get("vulnerabilities", []) if v["severity"] == "LOW"),
                },
            }
            for s in self._active_scans.values()
        ]

    # ── Helpers for dedup integration ────────────────────────────────────

    @staticmethod
    def _finding_to_dict(f: VulnerabilityFinding) -> Dict:
        """Convert a VulnerabilityFinding to dict for the dedup engine."""
        return {
            "vuln_type": f.vuln_type,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "verified": getattr(f, "verified", False),
            "request_evidence": getattr(f, "request_evidence", ""),
            "response_evidence": getattr(f, "response_evidence", ""),
            "title": f.title,
            "description": f.description,
            "impact": f.impact,
            "remediation": f.remediation,
            "cwe_id": f.cwe_id,
            "ml_prediction": f.ml_prediction,
            "ml_confidence": f.ml_confidence,
            "anomaly_score": f.anomaly_score,
            "http_method": f.http_method,
            "status_code": f.status_code,
            "response_time_ms": f.response_time_ms,
        }

    @staticmethod
    def _rebuild_findings(
        dedup_vulns: list, raw_findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """Pick the best raw finding for each deduplicated vulnerability."""
        rebuilt: List[VulnerabilityFinding] = []
        for dv in dedup_vulns:
            # find the raw finding with the highest confidence that matches
            best = None
            for f in raw_findings:
                if (
                    f.vuln_type == dv.vuln_type
                    and f.url.rstrip("/").split("?")[0] == dv.endpoint_url.rstrip("/").split("?")[0]
                ):
                    if best is None or f.confidence > best.confidence:
                        best = f
            if best:
                rebuilt.append(best)
        return rebuilt

    def _handle_agent_event(self, scan_id: str, event: Dict):
        """Handle agent events synchronously (used in non-async contexts)."""
        state = self._active_scans.get(scan_id)
        if state:
            state["agent_logs"].append({
                "timestamp": datetime.utcnow().isoformat(),
                **event,
            })
