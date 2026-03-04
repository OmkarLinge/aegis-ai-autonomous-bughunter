import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Activity, Globe, Bug, Shield, AlertTriangle, BookOpen,
  Wrench, ZoomIn, ZoomOut, Maximize2, Filter
} from 'lucide-react'
import { PageHeader, EmptyState, StatCard } from '../components/shared/index.jsx'

// ── Node visual styles ──────────────────────────────────────────────────────
const NODE_CONFIG = {
  endpoint:      { color: '#3b82f6', icon: '🌐', label: 'Endpoint',      shape: 'circle' },
  vulnerability: { color: '#ef4444', icon: '⚠️', label: 'Vulnerability', shape: 'diamond' },
  cve:           { color: '#f59e0b', icon: '🛡️', label: 'CVE',           shape: 'hexagon' },
  impact:        { color: '#dc2626', icon: '💥', label: 'Impact',        shape: 'triangle' },
  mitigation:    { color: '#10b981', icon: '🔧', label: 'Mitigation',    shape: 'rect' },
}

const EDGE_COLORS = {
  vuln_link:       '#6366f1',
  cve_link:        '#f59e0b',
  impact_link:     '#ef4444',
  mitigation_link: '#10b981',
}

// ── Layout engine (force-directed with simple spring model) ─────────────────
function layoutGraph(nodes, edges, width, height) {
  if (nodes.length === 0) return []

  // Assign initial positions by type columns
  const typeColumns = { endpoint: 0.15, vulnerability: 0.35, cve: 0.55, impact: 0.75, mitigation: 0.90 }
  const typeCounters = {}

  const positioned = nodes.map(n => {
    const type = n.type || 'endpoint'
    typeCounters[type] = (typeCounters[type] || 0) + 1
    const col = typeColumns[type] || 0.5
    const typeTotal = nodes.filter(nn => nn.type === type).length
    const row = typeCounters[type] / (typeTotal + 1)

    return {
      ...n,
      x: col * width + (Math.random() - 0.5) * 60,
      y: row * height + (Math.random() - 0.5) * 40,
    }
  })

  // Simple spring-based iterations
  const nodeMap = {}
  positioned.forEach(n => { nodeMap[n.id] = n })

  for (let iter = 0; iter < 80; iter++) {
    // Repulsion between all nodes
    for (let i = 0; i < positioned.length; i++) {
      for (let j = i + 1; j < positioned.length; j++) {
        const a = positioned[i], b = positioned[j]
        let dx = b.x - a.x, dy = b.y - a.y
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
        const force = 2000 / (dist * dist)
        const fx = (dx / dist) * force, fy = (dy / dist) * force
        a.x -= fx; a.y -= fy
        b.x += fx; b.y += fy
      }
    }
    // Attraction along edges
    for (const edge of edges) {
      const a = nodeMap[edge.from], b = nodeMap[edge.to]
      if (!a || !b) continue
      let dx = b.x - a.x, dy = b.y - a.y
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
      const force = (dist - 150) * 0.01
      const fx = (dx / dist) * force, fy = (dy / dist) * force
      a.x += fx; a.y += fy
      b.x -= fx; b.y -= fy
    }
    // Gravity toward center
    for (const n of positioned) {
      n.x += (width / 2 - n.x) * 0.005
      n.y += (height / 2 - n.y) * 0.005
    }
  }

  // Clamp
  for (const n of positioned) {
    n.x = Math.max(50, Math.min(width - 50, n.x))
    n.y = Math.max(50, Math.min(height - 50, n.y))
  }

  return positioned
}


// ═════════════════════════════════════════════════════════════════════════════
// Main page
// ═════════════════════════════════════════════════════════════════════════════

export default function SecurityGraph() {
  const { scanId: paramScanId } = useParams()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(paramScanId || '')
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [typeFilter, setTypeFilter] = useState('ALL')
  const svgRef = useRef(null)
  const isDragging = useRef(false)
  const lastPos = useRef({ x: 0, y: 0 })

  const W = 1200, H = 800

  // Fetch scans
  useEffect(() => {
    fetch('/api/scans').then(r => r.json())
      .then(d => {
        const list = d.scans || []
        setScans(list)
        if (!selectedScan && list.length > 0) {
          const completed = list.filter(s => s.status === 'completed')
          if (completed.length > 0) setSelectedScan(completed[0].scan_id)
        }
      }).catch(() => {})
  }, [])

  // Fetch knowledge graph
  useEffect(() => {
    if (!selectedScan) return
    setLoading(true)
    fetch(`/api/scans/${selectedScan}/knowledge-graph`)
      .then(r => r.json())
      .then(d => { setGraphData(d); setLoading(false) })
      .catch(() => { setGraphData(null); setLoading(false) })
  }, [selectedScan])

  // Layout
  const laidOut = useMemo(() => {
    if (!graphData?.nodes?.length) return []
    return layoutGraph(graphData.nodes, graphData.edges || [], W, H)
  }, [graphData])

  const nodeMap = useMemo(() => {
    const m = {}
    laidOut.forEach(n => { m[n.id] = n })
    return m
  }, [laidOut])

  // Filter
  const visibleNodes = useMemo(() => {
    if (typeFilter === 'ALL') return laidOut
    return laidOut.filter(n => n.type === typeFilter)
  }, [laidOut, typeFilter])

  const visibleIds = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes])

  const visibleEdges = useMemo(() => {
    if (!graphData?.edges) return []
    return graphData.edges.filter(e => visibleIds.has(e.from) && visibleIds.has(e.to))
  }, [graphData, visibleIds])

  // Pan handlers
  const onMouseDown = useCallback(e => {
    if (e.target.closest('.node-interactive')) return
    isDragging.current = true
    lastPos.current = { x: e.clientX, y: e.clientY }
  }, [])
  const onMouseMove = useCallback(e => {
    if (!isDragging.current) return
    setPan(p => ({
      x: p.x + (e.clientX - lastPos.current.x) / zoom,
      y: p.y + (e.clientY - lastPos.current.y) / zoom,
    }))
    lastPos.current = { x: e.clientX, y: e.clientY }
  }, [zoom])
  const onMouseUp = useCallback(() => { isDragging.current = false }, [])

  // Type counts
  const typeCounts = useMemo(() => {
    const c = {}
    laidOut.forEach(n => { c[n.type] = (c[n.type] || 0) + 1 })
    return c
  }, [laidOut])

  if (scans.length === 0 && !loading) {
    return (
      <div className="p-8">
        <PageHeader title="Security Knowledge Graph" subtitle="Visual security intelligence map" />
        <EmptyState
          icon={Globe}
          title="No scans yet"
          description="Run a scan to generate the knowledge graph."
          action={<Link to="/scan/new" className="btn-primary text-sm px-4 py-2 rounded-lg bg-aegis-accent text-white">Start a Scan</Link>}
        />
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between">
        <PageHeader
          title="Security Knowledge Graph"
          subtitle="Interactive map of endpoints, vulnerabilities, CVEs, impacts, and mitigations"
        />
        <select
          value={selectedScan}
          onChange={e => { setSelectedScan(e.target.value); setSelectedNode(null) }}
          className="bg-aegis-surface border border-aegis-border text-aegis-text text-sm rounded-lg px-3 py-2 font-mono"
        >
          <option value="">Select scan…</option>
          {scans.map(s => (
            <option key={s.scan_id} value={s.scan_id}>{s.target_url} — {s.status}</option>
          ))}
        </select>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20">
          <Activity className="animate-spin" size={20} />
          <span className="ml-2 text-aegis-muted font-mono text-sm">Building knowledge graph…</span>
        </div>
      )}

      {!loading && graphData && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Endpoints" value={typeCounts.endpoint || 0} icon={Globe} color="indigo" />
            <StatCard label="Vulnerabilities" value={typeCounts.vulnerability || 0} icon={Bug} color="red" />
            <StatCard label="CVEs" value={typeCounts.cve || 0} icon={Shield} color="amber" />
            <StatCard label="Impacts" value={typeCounts.impact || 0} icon={AlertTriangle} color="red" />
            <StatCard label="Mitigations" value={typeCounts.mitigation || 0} icon={Wrench} color="green" />
          </div>

          {/* Controls */}
          <div className="flex items-center justify-between">
            <div className="flex gap-2">
              {['ALL', 'endpoint', 'vulnerability', 'cve', 'impact', 'mitigation'].map(t => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                    typeFilter === t
                      ? 'bg-aegis-accent/20 text-aegis-accent border-aegis-accent/40'
                      : 'text-aegis-muted border-aegis-border hover:bg-aegis-card'
                  }`}
                >
                  {t === 'ALL' ? 'All' : NODE_CONFIG[t]?.label || t} ({t === 'ALL' ? laidOut.length : typeCounts[t] || 0})
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setZoom(z => Math.min(z + 0.2, 3))} className="p-2 rounded-lg border border-aegis-border text-aegis-muted hover:text-white"><ZoomIn size={14} /></button>
              <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))} className="p-2 rounded-lg border border-aegis-border text-aegis-muted hover:text-white"><ZoomOut size={14} /></button>
              <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }} className="p-2 rounded-lg border border-aegis-border text-aegis-muted hover:text-white"><Maximize2 size={14} /></button>
              <span className="text-xs font-mono text-aegis-muted">{(zoom * 100).toFixed(0)}%</span>
            </div>
          </div>

          {/* Graph canvas */}
          <div className="card overflow-hidden" style={{ height: 600 }}>
            <svg
              ref={svgRef}
              width="100%" height="100%"
              viewBox={`0 0 ${W} ${H}`}
              className="cursor-grab active:cursor-grabbing"
              onMouseDown={onMouseDown}
              onMouseMove={onMouseMove}
              onMouseUp={onMouseUp}
              onMouseLeave={onMouseUp}
            >
              <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                {/* Edges */}
                {visibleEdges.map((e, i) => {
                  const from = nodeMap[e.from], to = nodeMap[e.to]
                  if (!from || !to) return null
                  const color = EDGE_COLORS[e.type] || '#475569'
                  return (
                    <g key={`e${i}`}>
                      <line
                        x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                        stroke={color} strokeWidth={1.5} opacity={0.4}
                      />
                      {/* Arrow */}
                      <circle cx={to.x + (from.x - to.x) * 0.12} cy={to.y + (from.y - to.y) * 0.12} r={3} fill={color} opacity={0.6} />
                      {/* Edge label */}
                      <text
                        x={(from.x + to.x) / 2}
                        y={(from.y + to.y) / 2 - 6}
                        textAnchor="middle" fontSize={8} fill="#64748b" opacity={0.7}
                      >{e.label}</text>
                    </g>
                  )
                })}

                {/* Nodes */}
                {visibleNodes.map(node => {
                  const cfg = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint
                  const isHovered = hoveredNode === node.id
                  const isSelected = selectedNode === node.id
                  const r = isHovered || isSelected ? 22 : 18

                  return (
                    <g
                      key={node.id}
                      className="node-interactive cursor-pointer"
                      onMouseEnter={() => setHoveredNode(node.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                    >
                      {/* Glow */}
                      {(isHovered || isSelected) && (
                        <circle cx={node.x} cy={node.y} r={r + 6} fill={cfg.color} opacity={0.15} />
                      )}
                      {/* Shape */}
                      <circle
                        cx={node.x} cy={node.y} r={r}
                        fill={cfg.color}
                        opacity={isSelected ? 1 : isHovered ? 0.9 : 0.7}
                        stroke={isSelected ? '#fff' : cfg.color}
                        strokeWidth={isSelected ? 2 : 0}
                      />
                      {/* Icon */}
                      <text x={node.x} y={node.y + 5} textAnchor="middle" fontSize={14}>
                        {cfg.icon}
                      </text>
                      {/* Label */}
                      <text
                        x={node.x} y={node.y + r + 14}
                        textAnchor="middle" fontSize={9}
                        fill="#e2e8f0" fontFamily="monospace"
                      >
                        {(node.label || '').slice(0, 25)}
                      </text>
                    </g>
                  )
                })}
              </g>
            </svg>
          </div>

          {/* Legend */}
          <div className="flex items-center justify-center gap-6 text-xs text-aegis-muted">
            {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
              <span key={type} className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: cfg.color }} />
                {cfg.label}
              </span>
            ))}
          </div>

          {/* Selected node detail */}
          {selectedNode && nodeMap[selectedNode] && (
            <NodeDetail node={nodeMap[selectedNode]} edges={graphData.edges || []} nodeMap={nodeMap} />
          )}
        </>
      )}
    </div>
  )
}


// ── Node detail panel ───────────────────────────────────────────────────────
function NodeDetail({ node, edges, nodeMap }) {
  const cfg = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint
  const incoming = edges.filter(e => e.to === node.id).map(e => ({ ...e, node: nodeMap[e.from] })).filter(e => e.node)
  const outgoing = edges.filter(e => e.from === node.id).map(e => ({ ...e, node: nodeMap[e.to] })).filter(e => e.node)

  return (
    <div className="card p-5 space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-2xl">{cfg.icon}</span>
        <div>
          <h3 className="font-semibold text-white text-sm">{node.label}</h3>
          <span className="text-xs font-mono text-aegis-muted uppercase">{cfg.label}</span>
        </div>
        {node.severity && (
          <span className={`ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded ${
            node.severity === 'CRITICAL' ? 'bg-red-600/50 text-red-300' :
            node.severity === 'HIGH' ? 'bg-orange-600/50 text-orange-300' :
            'bg-amber-600/50 text-amber-300'
          }`}>{node.severity}</span>
        )}
        {node.cvss_score && (
          <span className="text-xs font-mono text-amber-400">CVSS {node.cvss_score}</span>
        )}
      </div>

      {(node.description || node.full_text || node.product) && (
        <p className="text-xs text-aegis-muted leading-relaxed">
          {node.product && <strong className="text-aegis-text">{node.product} — </strong>}
          {node.full_text || node.description || ''}
        </p>
      )}

      <div className="grid grid-cols-2 gap-4">
        {incoming.length > 0 && (
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-aegis-muted mb-2">Incoming Connections</h4>
            <div className="space-y-1">
              {incoming.map((e, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span>{NODE_CONFIG[e.node.type]?.icon || '•'}</span>
                  <span className="text-aegis-text truncate">{e.node.label}</span>
                  <span className="text-aegis-muted/50 ml-auto">{e.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {outgoing.length > 0 && (
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-aegis-muted mb-2">Outgoing Connections</h4>
            <div className="space-y-1">
              {outgoing.map((e, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span>{NODE_CONFIG[e.node.type]?.icon || '•'}</span>
                  <span className="text-aegis-text truncate">{e.node.label}</span>
                  <span className="text-aegis-muted/50 ml-auto">{e.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
