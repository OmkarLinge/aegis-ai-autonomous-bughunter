"""
Aegis AI — FastAPI Backend
Main API server with REST endpoints and WebSocket for real-time updates.
"""
import asyncio
import json
import os
from typing import Dict, List, Set, Optional
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, validator

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.orchestrator import ScanOrchestrator
from backend.scheduler.scan_scheduler import ScanScheduler
from utils.config import config
from utils.logger import get_logger

logger = get_logger(__name__, "ORCHESTRATOR")

# ── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis AI — Autonomous Bug Hunter",
    description=(
        "Agentic AI system that autonomously explores web applications, "
        "detects vulnerabilities, and generates professional security reports."
    ),
    version=config.version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.cors_origins + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Connection Manager ─────────────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections, grouped by scan_id."""

    def __init__(self):
        self.active: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        if scan_id not in self.active:
            self.active[scan_id] = set()
        self.active[scan_id].add(ws)
        logger.info(f"WebSocket connected for scan {scan_id}")

    def disconnect(self, scan_id: str, ws: WebSocket):
        if scan_id in self.active:
            self.active[scan_id].discard(ws)

    async def broadcast(self, scan_id: str, message: Dict):
        """Broadcast message to all clients watching this scan."""
        if scan_id not in self.active:
            return
        dead = set()
        for ws in self.active[scan_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active[scan_id].discard(ws)


ws_manager = ConnectionManager()

# Orchestrator with WebSocket broadcaster
async def ws_broadcaster(scan_id: str, event: Dict):
    await ws_manager.broadcast(scan_id, event)

orchestrator = ScanOrchestrator(websocket_broadcaster=ws_broadcaster)
scheduler = ScanScheduler(run_scan_fn=orchestrator.start_scan)


@app.on_event("startup")
async def startup_event():
    await scheduler.start()


@app.on_event("shutdown")
async def shutdown_event():
    await scheduler.stop()


# ── Pydantic Models ──────────────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    target_url: str
    scan_depth: int = 3
    scan_types: List[str] = ["sql_injection", "xss", "open_redirect", "security_headers"]
    authorized: bool = False
    target_name: Optional[str] = None

    @validator("scan_depth")
    def validate_depth(cls, v):
        if not 1 <= v <= 5:
            raise ValueError("scan_depth must be between 1 and 5")
        return v

    @validator("target_url")
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("target_url is required")
        # Auto-prepend scheme if missing
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class ScanResponse(BaseModel):
    scan_id: str
    message: str
    target_url: str
    status: str


# ── REST API Routes ──────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": config.version,
        "disclaimer": config.disclaimer,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/scans", response_model=ScanResponse)
async def start_scan(request: StartScanRequest):
    """Start a new security scan."""
    if not request.authorized:
        raise HTTPException(
            status_code=400,
            detail=(
                "You must confirm authorization to scan the target. "
                "Only scan systems you own or have explicit written permission to test."
            )
        )

    try:
        scan_id = await orchestrator.start_scan(
            target_url=request.target_url,
            scan_depth=request.scan_depth,
            scan_types=request.scan_types,
            authorized=request.authorized,
            target_name=request.target_name,
        )
        return ScanResponse(
            scan_id=scan_id,
            message=f"Scan started for {request.target_url}",
            target_url=request.target_url,
            status="running",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scan")


@app.get("/api/scans")
async def list_scans():
    """List all scans."""
    return {"scans": orchestrator.get_all_scans()}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details and current state."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return state


@app.get("/api/scans/{scan_id}/endpoints")
async def get_endpoints(scan_id: str):
    """Get discovered endpoints for a scan."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"endpoints": state.get("endpoints", [])}


@app.get("/api/scans/{scan_id}/vulnerabilities")
async def get_vulnerabilities(scan_id: str):
    """Get vulnerability findings for a scan."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"vulnerabilities": state.get("vulnerabilities", [])}


@app.get("/api/scans/{scan_id}/logs")
async def get_agent_logs(scan_id: str):
    """Get agent activity logs for a scan."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "logs": state.get("agent_logs", []),
        "reasoning": state.get("reasoning", []),
    }


@app.get("/api/scans/{scan_id}/attack-graph")
async def get_attack_graph(scan_id: str):
    """Get attack graph visualization data with paths and risk propagation."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    graph = state.get("attack_graph", {})
    if not graph:
        return {"nodes": [], "edges": [], "paths": [], "risk_summary": {}, "risk_propagation": {}}
    return graph


@app.get("/api/scans/{scan_id}/attack-chains")
async def get_attack_chains(scan_id: str):
    """Get discovered multi-step attack chains."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    chains = state.get("attack_chains", {})
    if not chains:
        return {"chains": [], "stats": {"total_chains": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}
    return chains


@app.get("/api/scans/{scan_id}/risk-score")
async def get_risk_score(scan_id: str):
    """Get computed security risk score for a scan."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    risk = state.get("risk_score", {})
    if not risk:
        return {"score": 100, "risk_level": "SECURE", "breakdown": {}, "details": {}, "recommendations": []}
    return risk


@app.get("/api/scans/{scan_id}/knowledge-graph")
async def get_knowledge_graph(scan_id: str):
    """Get security knowledge graph data (endpoints, vulns, CVEs, impacts, mitigations)."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    kg_nodes = []
    kg_edges = []
    node_ids = set()

    # Endpoints
    for ep in state.get("endpoints", []):
        nid = f"ep_{ep.get('path', ep.get('url', ''))}"
        if nid not in node_ids:
            node_ids.add(nid)
            kg_nodes.append({
                "id": nid, "label": ep.get("path", ep.get("url", "")),
                "type": "endpoint", "category": ep.get("endpoint_type", "unknown"),
                "risk": ep.get("risk_score", 0.3),
            })

    # Vulnerabilities + CVE + Impact + Mitigation
    for i, vuln in enumerate(state.get("vulnerabilities", [])):
        vid = f"vuln_{i}"
        if vid not in node_ids:
            node_ids.add(vid)
            kg_nodes.append({
                "id": vid, "label": vuln.get("title", vuln.get("vuln_type", "")),
                "type": "vulnerability", "severity": vuln.get("severity", "MEDIUM"),
                "confidence": vuln.get("confidence", 0.5),
            })

        # Link endpoint -> vuln
        vuln_url = vuln.get("url", "")
        for ep in state.get("endpoints", []):
            if ep.get("path", "") in vuln_url:
                ep_id = f"ep_{ep['path']}"
                if ep_id in node_ids:
                    kg_edges.append({"from": ep_id, "to": vid, "label": "has vulnerability", "type": "vuln_link"})
                break

        # CVE intel
        cve_intel = vuln.get("cve_intel", {})
        if cve_intel and cve_intel.get("enriched"):
            for cve in cve_intel.get("cve_examples", []):
                cve_id = cve["id"]
                cve_nid = f"cve_{cve_id}"
                if cve_nid not in node_ids:
                    node_ids.add(cve_nid)
                    kg_nodes.append({
                        "id": cve_nid, "label": cve_id,
                        "type": "cve", "product": cve.get("product", ""),
                        "description": cve.get("description", ""),
                        "cvss_score": cve_intel.get("cvss_score", 0),
                    })
                kg_edges.append({"from": vid, "to": cve_nid, "label": "maps to", "type": "cve_link"})

            # Impact node from CVE intel
            impact_text = cve_intel.get("impact", "")
            if impact_text:
                imp_id = f"impact_{vuln.get('vuln_type', i)}"
                if imp_id not in node_ids:
                    node_ids.add(imp_id)
                    kg_nodes.append({
                        "id": imp_id, "label": impact_text[:60],
                        "type": "impact", "full_text": impact_text,
                    })
                for cve in cve_intel.get("cve_examples", []):
                    kg_edges.append({"from": f"cve_{cve['id']}", "to": imp_id, "label": "causes", "type": "impact_link"})

            # Mitigation node
            mit_text = cve_intel.get("mitigation", "")
            if mit_text:
                mit_id = f"mit_{vuln.get('vuln_type', i)}"
                if mit_id not in node_ids:
                    node_ids.add(mit_id)
                    kg_nodes.append({
                        "id": mit_id, "label": mit_text[:60],
                        "type": "mitigation", "full_text": mit_text,
                    })
                for cve in cve_intel.get("cve_examples", []):
                    kg_edges.append({"from": f"cve_{cve['id']}", "to": mit_id, "label": "mitigated by", "type": "mitigation_link"})

    return {"nodes": kg_nodes, "edges": kg_edges, "node_count": len(kg_nodes), "edge_count": len(kg_edges)}


# ── Scheduler Endpoints ───────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    target_url: str
    frequency: str = "daily"
    scan_types: List[str] = ["sql_injection", "xss", "open_redirect", "security_headers"]
    scan_depth: int = 3
    target_name: Optional[str] = None
    custom_interval_hours: Optional[float] = None

    @validator("target_url")
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("target_url is required")
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


@app.get("/api/schedules")
async def list_schedules():
    """List all scheduled scans."""
    return {"schedules": scheduler.get_all_schedules()}


@app.post("/api/schedules")
async def create_schedule(request: ScheduleRequest):
    """Create a new scheduled scan."""
    sched = scheduler.add_schedule(
        target_url=request.target_url,
        frequency=request.frequency,
        scan_types=request.scan_types,
        scan_depth=request.scan_depth,
        target_name=request.target_name,
        custom_interval_hours=request.custom_interval_hours,
    )
    return {"message": "Schedule created", "schedule": scheduler._serialize(sched)}


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Delete a scheduled scan."""
    removed = scheduler.remove_schedule(schedule_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"message": f"Schedule {schedule_id} deleted"}


@app.patch("/api/schedules/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str):
    """Enable or disable a scheduled scan."""
    result = scheduler.toggle_schedule(schedule_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"enabled": result}


@app.get("/api/scans/{scan_id}/report/{format}")
async def download_report(scan_id: str, format: str):
    """Download a generated report (pdf, json, markdown)."""
    state = orchestrator.get_scan_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state["status"] != "completed":
        raise HTTPException(status_code=400, detail="Report not yet available")

    report_paths = state.get("report_paths", {})
    format_map = {
        "pdf": ("pdf", "application/pdf", f"aegis_report_{scan_id}.pdf"),
        "json": ("json", "application/json", f"aegis_report_{scan_id}.json"),
        "markdown": ("markdown", "text/markdown", f"aegis_report_{scan_id}.md"),
        "md": ("markdown", "text/markdown", f"aegis_report_{scan_id}.md"),
    }

    if format not in format_map:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}")

    key, mime, filename = format_map[format]
    file_path = report_paths.get(key)

    if not file_path or not Path(file_path).exists():
        raise HTTPException(status_code=404, detail=f"Report file not found")

    return FileResponse(
        path=file_path,
        media_type=mime,
        filename=filename,
    )


@app.delete("/api/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    cancelled = orchestrator.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=400, detail="Scan not found or already complete")
    return {"message": f"Scan {scan_id} cancelled"}


@app.get("/api/stats")
async def get_stats():
    """Get aggregate statistics across all scans."""
    scans = orchestrator.get_all_scans()
    total_vulns = sum(s["vulnerability_count"] for s in scans)
    total_endpoints = sum(s["endpoint_count"] for s in scans)

    return {
        "total_scans": len(scans),
        "completed_scans": sum(1 for s in scans if s["status"] == "completed"),
        "running_scans": sum(1 for s in scans if s["status"] == "running"),
        "total_vulnerabilities": total_vulns,
        "total_endpoints": total_endpoints,
        "severity_breakdown": {
            "critical": sum(s["severity_summary"]["critical"] for s in scans),
            "high": sum(s["severity_summary"]["high"] for s in scans),
            "medium": sum(s["severity_summary"]["medium"] for s in scans),
            "low": sum(s["severity_summary"]["low"] for s in scans),
        },
    }


# ── WebSocket Endpoint ───────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket connection for real-time scan updates.
    
    Client connects to /ws/{scan_id} to receive live events
    from all agents as the scan progresses.
    """
    await ws_manager.connect(scan_id, websocket)
    
    # Send current scan state immediately on connect
    state = orchestrator.get_scan_state(scan_id)
    if state:
        await websocket.send_json({
            "type": "state_sync",
            "scan_id": scan_id,
            "data": {
                "status": state["status"],
                "progress": state.get("progress", 0),
                "endpoint_count": len(state.get("endpoints", [])),
                "vulnerability_count": len(state.get("vulnerabilities", [])),
                "logs": state.get("agent_logs", [])[-20:],  # Last 20 logs
            },
            "timestamp": datetime.utcnow().isoformat(),
        })

    try:
        while True:
            # Keep connection alive, receive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
        logger.info(f"WebSocket disconnected for scan {scan_id}")


# ── Serve React Frontend in Production ──────────────────────────────────────
frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting Aegis AI server on {config.api.host}:{config.api.port}")
    logger.info(config.disclaimer)
    uvicorn.run(
        "backend.main:app",
        host=config.api.host,
        port=config.api.port,
        reload=config.api.reload,
        log_level="info",
    )
