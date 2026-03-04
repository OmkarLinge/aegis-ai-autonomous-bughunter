import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Activity, Shield, Bug, Globe, ChevronRight,
  Cpu, Search, Zap, Brain, FileText, AlertTriangle,
  CheckCircle, Clock, ArrowLeft, ExternalLink
} from 'lucide-react'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  ResponsiveContainer, Tooltip
} from 'recharts'
import { StatusBadge, SeverityBadge, TerminalLog, ProgressBar, EmptyState } from '../components/shared/index.jsx'

const AGENT_META = {
  RECON: { icon: Search, color: 'text-cyan-400', bg: 'bg-cyan-950/30 border-cyan-800', label: 'Recon Agent' },
  ENDPOINT: { icon: Globe, color: 'text-blue-400', bg: 'bg-blue-950/30 border-blue-800', label: 'Endpoint Intel' },
  STRATEGY: { icon: Brain, color: 'text-emerald-400', bg: 'bg-emerald-950/30 border-emerald-800', label: 'Strategy Agent' },
  EXPLOIT: { icon: Zap, color: 'text-red-400', bg: 'bg-red-950/30 border-red-800', label: 'Exploit Agent' },
  CLASSIFIER: { icon: Cpu, color: 'text-purple-400', bg: 'bg-purple-950/30 border-purple-800', label: 'ML Classifier' },
  REPORT: { icon: FileText, color: 'text-white', bg: 'bg-slate-800 border-slate-600', label: 'Report Agent' },
  ORCHESTRATOR: { icon: Shield, color: 'text-indigo-400', bg: 'bg-indigo-950/30 border-indigo-800', label: 'Orchestrator' },
}

const SCAN_PHASES = [
  { id: 'RECON', label: 'Reconnaissance', pct: [0, 30] },
  { id: 'ENDPOINT', label: 'Classification', pct: [30, 50] },
  { id: 'STRATEGY', label: 'Strategy', pct: [50, 60] },
  { id: 'EXPLOIT', label: 'Testing', pct: [60, 85] },
  { id: 'REPORT', label: 'Reporting', pct: [85, 100] },
]

export default function LiveScan() {
  const { scanId: paramScanId } = useParams()
  const [scans, setScans] = useState([])
  const [activeScan, setActiveScan] = useState(null)
  const [logs, setLogs] = useState([])
  const [reasoning, setReasoning] = useState([])
  const [activeTab, setActiveTab] = useState('logs')
  const wsRef = useRef(null)

  // Load all scans for sidebar
  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(d => setScans(d.scans || []))
  }, [])

  // Load selected scan
  const loadScan = useCallback(async (id) => {
    const res = await fetch(`/api/scans/${id}`)
    if (res.ok) {
      const data = await res.json()
      setActiveScan(data)
      setLogs(data.agent_logs || [])
      setReasoning(data.reasoning || [])
    }
  }, [])

  useEffect(() => {
    const id = paramScanId || scans[0]?.scan_id
    if (!id) return
    loadScan(id)

    // WebSocket for live updates
    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const wsHost = window.location.host
    const ws = new WebSocket(`${wsProto}://${wsHost}/ws/${id}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      const event = JSON.parse(e.data)
      if (event.type === 'state_sync') {
        setLogs(prev => [...prev, ...(event.data?.logs || [])])
      } else if (event.type === 'agent_event') {
        setLogs(prev => [...prev.slice(-200), {
          timestamp: event.timestamp,
          agent: event.agent,
          message: event.message,
          event_type: event.event_type,
        }])
        if (event.type === 'agent_event') {
          loadScan(id)
        }
      } else if (['scan_complete', 'scan_failed', 'exploit_complete', 'recon_complete'].includes(event.type)) {
        loadScan(id)
      }
    }

    ws.onerror = () => ws.close()

    // Polling fallback every 3s
    const poll = setInterval(() => loadScan(id), 3000)

    return () => {
      ws.close()
      clearInterval(poll)
    }
  }, [paramScanId, scans[0]?.scan_id])

  const currentAgent = activeScan?.current_agent
  const progress = activeScan?.progress || 0
  const vulns = activeScan?.vulnerabilities || []
  const endpoints = activeScan?.endpoints || []
  const reasoning_log = activeScan?.reasoning || reasoning

  const severityCounts = {
    CRITICAL: vulns.filter(v => v.severity === 'CRITICAL').length,
    HIGH: vulns.filter(v => v.severity === 'HIGH').length,
    MEDIUM: vulns.filter(v => v.severity === 'MEDIUM').length,
    LOW: vulns.filter(v => v.severity === 'LOW').length,
  }

  return (
    <div className="flex h-full overflow-hidden">
      {/* Scan list sidebar */}
      <div className="w-64 border-r border-aegis-border bg-aegis-surface flex flex-col flex-shrink-0 overflow-y-auto">
        <div className="p-4 border-b border-aegis-border">
          <h2 className="font-semibold text-white text-sm">Active Scans</h2>
        </div>
        {scans.length === 0 ? (
          <div className="p-4 text-xs text-aegis-muted text-center mt-4">
            No scans yet.<br/>
            <Link to="/scan/new" className="text-aegis-accent mt-1 inline-block">Start one →</Link>
          </div>
        ) : (
          scans.map(s => (
            <Link
              key={s.scan_id}
              to={`/live/${s.scan_id}`}
              className={`block p-3 border-b border-aegis-border hover:bg-aegis-card/50 transition-colors ${
                activeScan?.scan_id === s.scan_id ? 'bg-aegis-card border-l-2 border-l-aegis-accent' : ''
              }`}
            >
              <div className="font-mono text-xs text-aegis-text truncate">{s.target_url}</div>
              <div className="flex items-center justify-between mt-1">
                <StatusBadge status={s.status} />
                <span className="text-xs text-aegis-muted">{s.vulnerability_count} vulns</span>
              </div>
              {s.status === 'running' && (
                <ProgressBar value={s.progress || 0} color="indigo" showPercent={false} />
              )}
            </Link>
          ))
        )}
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-y-auto">
        {!activeScan ? (
          <EmptyState
            icon={Activity}
            title="No scan selected"
            description="Select a scan from the sidebar or start a new one"
            action={<Link to="/scan/new" className="px-4 py-2 bg-aegis-accent text-white rounded-lg text-sm">New Scan</Link>}
          />
        ) : (
          <div className="p-6 space-y-6">
            {/* Scan header */}
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <StatusBadge status={activeScan.status} />
                  <span className="font-mono text-xs text-aegis-muted">ID: {activeScan.scan_id}</span>
                </div>
                <h1 className="text-xl font-display font-bold text-white">{activeScan.target_url}</h1>
                <p className="text-xs text-aegis-muted mt-1">
                  Started {new Date(activeScan.started_at).toLocaleString()}
                  {activeScan.duration_seconds && ` · Duration: ${activeScan.duration_seconds.toFixed(1)}s`}
                </p>
              </div>
              <Link to="/vulnerabilities" className="text-sm text-aegis-accent hover:text-aegis-accent-glow flex items-center gap-1">
                View Vulns <ChevronRight size={14} />
              </Link>
            </div>

            {/* Progress bar */}
            {activeScan.status === 'running' && (
              <div className="card p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-white">
                    {currentAgent ? `${AGENT_META[currentAgent]?.label || currentAgent} active...` : 'Initializing...'}
                  </span>
                  <span className="font-mono text-aegis-accent text-sm">{progress}%</span>
                </div>
                <div className="h-2 bg-aegis-surface rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-aegis-accent to-cyan-500 rounded-full transition-all duration-700 relative overflow-hidden"
                    style={{ width: `${progress}%` }}
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse" />
                  </div>
                </div>
                {/* Phase indicators */}
                <div className="flex justify-between mt-2">
                  {SCAN_PHASES.map(phase => (
                    <div key={phase.id} className={`text-xs font-mono ${
                      progress >= phase.pct[0] ? 'text-aegis-accent' : 'text-aegis-muted/40'
                    }`}>
                      {phase.label}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Stats row */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {[
                { label: 'Endpoints', value: endpoints.length, color: 'text-cyan-400' },
                { label: 'Vulnerabilities', value: vulns.length, color: 'text-red-400' },
                { label: 'Technologies', value: activeScan.technologies?.length || 0, color: 'text-blue-400' },
                { label: 'Agent Events', value: logs.length, color: 'text-emerald-400' },
              ].map(s => (
                <div key={s.label} className="card p-3 text-center">
                  <div className={`text-2xl font-display font-bold ${s.color}`}>{s.value}</div>
                  <div className="text-xs text-aegis-muted mt-1">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Severity counts */}
            {vulns.length > 0 && (
              <div className="grid grid-cols-4 gap-3">
                {Object.entries(severityCounts).map(([sev, count]) => (
                  <div key={sev} className={`card p-3 text-center ${count > 0 ? 'ring-1' : ''} ${
                    sev === 'CRITICAL' && count > 0 ? 'ring-red-900' :
                    sev === 'HIGH' && count > 0 ? 'ring-red-800' :
                    sev === 'MEDIUM' && count > 0 ? 'ring-amber-800' : ''
                  }`}>
                    <div className={`text-xl font-bold ${
                      sev === 'CRITICAL' ? 'text-red-500' :
                      sev === 'HIGH' ? 'text-red-400' :
                      sev === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'
                    }`}>{count}</div>
                    <SeverityBadge severity={sev} size="xs" />
                  </div>
                ))}
              </div>
            )}

            {/* Tabs */}
            <div>
              <div className="flex border-b border-aegis-border mb-4">
                {['logs', 'endpoints', 'reasoning', 'agents'].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${
                      activeTab === tab
                        ? 'text-aegis-accent border-b-2 border-aegis-accent'
                        : 'text-aegis-muted hover:text-aegis-text'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {/* Logs tab */}
              {activeTab === 'logs' && (
                <TerminalLog logs={logs} maxHeight="420px" />
              )}

              {/* Endpoints tab */}
              {activeTab === 'endpoints' && (
                <div className="space-y-2 max-h-[420px] overflow-y-auto">
                  {endpoints.length === 0 ? (
                    <div className="text-center py-8 text-aegis-muted text-sm">No endpoints discovered yet</div>
                  ) : endpoints.map((ep, i) => (
                    <div key={i} className="card px-4 py-3 flex items-center gap-4">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                        ep.status_code >= 200 && ep.status_code < 300 ? 'text-emerald-400 border-emerald-800 bg-emerald-950/30' :
                        ep.status_code >= 300 && ep.status_code < 400 ? 'text-blue-400 border-blue-800 bg-blue-950/30' :
                        'text-red-400 border-red-800 bg-red-950/30'
                      }`}>
                        {ep.status_code || '—'}
                      </span>
                      <span className="font-mono text-sm text-aegis-text flex-1 truncate">{ep.path}</span>
                      {ep.endpoint_type && ep.endpoint_type !== 'unknown' && (
                        <span className="text-xs text-aegis-muted bg-aegis-surface px-2 py-0.5 rounded border border-aegis-border">
                          {ep.endpoint_type}
                        </span>
                      )}
                      {ep.forms_count > 0 && (
                        <span className="text-xs text-amber-400">📋 {ep.forms_count} form(s)</span>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Reasoning tab */}
              {activeTab === 'reasoning' && (
                <div className="space-y-2 max-h-[420px] overflow-y-auto">
                  {reasoning_log.length === 0 ? (
                    <div className="text-center py-8 text-aegis-muted text-sm">Agent reasoning will appear here</div>
                  ) : reasoning_log.map((thought, i) => (
                    <div key={i} className="flex gap-3 p-3 rounded-lg bg-aegis-surface border border-aegis-border">
                      <div className="w-6 h-6 bg-aegis-accent/20 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-mono text-aegis-accent">
                        {i + 1}
                      </div>
                      <p className="text-sm text-aegis-text leading-relaxed">{thought}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Agents tab */}
              {activeTab === 'agents' && (
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                  {Object.entries(AGENT_META).map(([key, meta]) => {
                    const agentLogs = logs.filter(l => l.agent === key)
                    const isActive = currentAgent === key
                    const Icon = meta.icon
                    return (
                      <div key={key} className={`card p-4 border ${meta.bg} ${isActive ? 'animate-pulse' : ''}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <Icon size={16} className={meta.color} />
                          <span className={`text-sm font-semibold ${meta.color}`}>{meta.label}</span>
                          {isActive && (
                            <span className="ml-auto text-xs text-aegis-accent animate-pulse">● ACTIVE</span>
                          )}
                        </div>
                        <div className="text-xs text-aegis-muted">{agentLogs.length} events</div>
                        {agentLogs.length > 0 && (
                          <div className="mt-2 text-xs text-aegis-muted font-mono truncate">
                            {agentLogs[agentLogs.length - 1]?.message}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
