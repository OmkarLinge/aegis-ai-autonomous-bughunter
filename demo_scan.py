#!/usr/bin/env python3
"""
Aegis AI — CLI Demo Scanner
Runs a complete scan from the command line without the web UI.
Usage: python demo_scan.py <target_url>
"""
import asyncio
import sys
import json
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


async def run_demo_scan(target_url: str):
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║             AEGIS AI — CLI Demo Scanner                   ║
╚═══════════════════════════════════════════════════════════╝

⚠️  AUTHORIZED USE ONLY

Target: {target_url}
""")

    from utils.config import config
    from utils.logger import get_logger
    from agents.recon_agent import ReconAgent
    from agents.endpoint_intelligence_agent import EndpointIntelligenceAgent
    from agents.exploit_agent import ExploitAgent
    from agents.strategy_agent import StrategyAgent
    from reports.report_generator import ReportAgent, ReportData
    import time

    logger = get_logger("demo", "ORCHESTRATOR")

    # Confirm authorization
    answer = input("Do you have authorization to scan this target? [yes/no]: ").strip().lower()
    if answer != "yes":
        print("Scan aborted — authorization required.")
        return

    scan_id = f"DEMO-{int(time.time())}"
    start = time.monotonic()

    all_logs = []
    async def on_event(event):
        msg = f"[{event['agent']:12}] {event['message']}"
        print(msg)
        all_logs.append(event)

    # Phase 1: Recon
    print("\n── Phase 1: Reconnaissance ─────────────────────────────")
    recon = ReconAgent(target_url, authorized=True, max_depth=2, on_event=on_event)
    recon_result = await recon.run()
    print(f"\n✓ Found {len(recon_result.endpoints)} endpoints")
    print(f"✓ Technologies: {', '.join(recon_result.technologies) or 'none detected'}")

    # Phase 2: Classify
    print("\n── Phase 2: Endpoint Intelligence ──────────────────────")
    intel = EndpointIntelligenceAgent(on_event=on_event)
    classified = await intel.analyze(recon_result.endpoints)
    print(f"\n✓ Classified {len(classified)} endpoints")

    # Phase 3: Strategy
    print("\n── Phase 3: Strategy Planning ────────────────────────────")
    strategy_agent = StrategyAgent(target_url)
    strategy = strategy_agent.plan_scan(classified)
    print(f"✓ Risk level: {strategy.risk_level}")
    for thought in strategy_agent.reasoning_log:
        print(f"  🧠 {thought}")

    # Phase 4: Exploit
    print("\n── Phase 4: Vulnerability Testing ──────────────────────")
    exploit = ExploitAgent(target_url, authorized=True, on_event=on_event)
    findings = await exploit.run_all(strategy.target_endpoints)

    print(f"\n✓ Testing complete: {len(findings)} findings")
    for f in findings:
        print(f"  [{f.severity:8}] {f.title} — {f.url}")

    # Phase 5: Report
    print("\n── Phase 5: Report Generation ───────────────────────────")
    duration = time.monotonic() - start
    report_data = ReportData(
        scan_id=scan_id,
        target_url=target_url,
        findings=findings,
        endpoints_count=len(recon_result.endpoints),
        technologies=recon_result.technologies,
        scan_duration_seconds=duration,
        agent_reasoning=recon_result.agent_reasoning + strategy_agent.reasoning_log,
    )

    reporter = ReportAgent()
    paths = await reporter.generate(report_data)

    print("\n══════════════════════════════════════════════════════")
    print(f"  SCAN COMPLETE in {duration:.1f}s")
    print(f"  Endpoints:       {len(recon_result.endpoints)}")
    print(f"  Vulnerabilities: {len(findings)}")
    print(f"  Risk Rating:     {report_data.risk_rating}")
    print()
    for fmt, path in paths.items():
        if path:
            print(f"  📄 {fmt.upper()} Report: {path}")
    print("══════════════════════════════════════════════════════\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python demo_scan.py <target_url>")
        print("Example: python demo_scan.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(run_demo_scan(target))
