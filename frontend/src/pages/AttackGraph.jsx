import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Shield, AlertTriangle, ArrowLeft, Network, Zap,
  Target, Database, ChevronRight, TrendingUp, Eye
} from 'lucide-react'
import { SeverityBadge, StatusBadge, PageHeader } from '../components/shared/index.jsx'

const API = '/api'

/* ── colour / shape helpers ───────────────────────────────────────────────── */
const NODE_STYLES = {
  attacker:       { fill: '#6366f1', stroke: '#818cf8', icon: '⚡', radius: 28 },
  endpoint:       { fill: '#3b82f6', stroke: '#60a5fa', icon: '🌐', radius: 22 },
  category:       { fill: '#0ea5e9', stroke: '#38bdf8', icon: '📂', radius: 24 },
  vulnerability:  { fill: '#ef4444', stroke: '#f87171', icon: '🐛', radius: 22 },
  impact:         { fill: '#991b1b', stroke: '#ef4444', icon: '💥', radius: 26 },
  root:           { fill: '#4f46e5', stroke: '#818cf8', icon: '🎯', radius: 28 },
  unknown:        { fill: '#6b7280', stroke: '#9ca3af', icon: '❓', radius: 18 },
}

const EDGE_COLORS = {
  discovery: '#60a5fa',
  exploit:   '#f87171',
  impact:    '#ef4444',
  contains:  '#94a3b8',
  chain:     '#fbbf24',
}

const RISK_COLORS = [
  { min: 0,   color: '#10b981', label: 'Low' },
  { min: 4,   color: '#f59e0b', label: 'Medium' },
  { min: 6,   color: '#ef4444', label: 'High' },
  { min: 8,   color: '#991b1b', label: 'Critical' },
]

function riskColor(score) {
  let c = RISK_COLORS[0].color
  for (const r of RISK_COLORS) if (score >= r.min) c = r.color
  return c
}

/* ── Dagre-like layered layout (pure JS, no dependency) ──────────────────── */
function layoutGraph(nodes, edges) {
  if (!nodes.length) return { positioned: [], layoutEdges: [] }

  // Build adjacency & in-degree
  const adj = {}, inDeg = {}
  nodes.forEach(n => { adj[n.id] = []; inDeg[n.id] = 0 })
  edges.forEach(e => {
    const from = e.from || e.source
    const to = e.to || e.target
    if (adj[from]) adj[from].push(to)
    if (inDeg[to] !== undefined) inDeg[to]++
  })

  // Topological sort for layers
  const layers = []
  const visited = new Set()
  const queue = Object.keys(inDeg).filter(k => inDeg[k] === 0)
  if (queue.length === 0 && nodes.length) queue.push(nodes[0].id) // fallback

  while (queue.length) {
    const layer = [...queue]
    layers.push(layer)
    layer.forEach(n => visited.add(n))
    queue.length = 0
    for (const n of layer) {
      for (const child of (adj[n] || [])) {
        inDeg[child]--
        if (inDeg[child] <= 0 && !visited.has(child)) {
          queue.push(child)
          visited.add(child)
        }
      }
    }
  }

  // Any unvisited → last layer
  const unvisited = nodes.filter(n => !visited.has(n.id)).map(n => n.id)
  if (unvisited.length) layers.push(unvisited)

  const LAYER_H = 140, NODE_W = 180
  const nodePos = {}
  layers.forEach((layer, li) => {
    const totalW = layer.length * NODE_W
    const startX = -totalW / 2 + NODE_W / 2
    layer.forEach((nid, ni) => {
      nodePos[nid] = { x: startX + ni * NODE_W, y: li * LAYER_H }
    })
  })

  // Center the canvas
  const xs = Object.values(nodePos).map(p => p.x)
  const ys = Object.values(nodePos).map(p => p.y)
  const minX = Math.min(...xs), maxX = Math.max(...xs)
  const minY = Math.min(...ys), maxY = Math.max(...ys)
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
  const padding = 60
  const width = maxX - minX + padding * 2
  const height = maxY - minY + padding * 2

  const positioned = nodes.map(n => ({
    ...n,
    x: (nodePos[n.id]?.x || 0) - minX + padding,
    y: (nodePos[n.id]?.y || 0) - minY + padding,
  }))

  const posMap = {}
  positioned.forEach(n => { posMap[n.id] = n })

  const layoutEdges = edges
    .map(e => {
      const from = posMap[e.from || e.source]
      const to = posMap[e.to || e.target]
      if (!from || !to) return null
      return { ...e, x1: from.x, y1: from.y, x2: to.x, y2: to.y }
    })
    .filter(Boolean)

  return { positioned, layoutEdges, width, height }
}

/* ── Main Component ──────────────────────────────────────────────────────── */
export default function AttackGraphPage() {
  const { scanId: paramScanId } = useParams()
  const [scans, setScans] = useState([])
  const [scanId, setScanId] = useState(paramScanId || null)
  const [graphData, setGraphData] = useState(null)
  const [scanState, setScanState] = useState(null)
  const [loading, setLoading] = useState(true)
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedPath, setSelectedPath] = useState(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const svgRef = useRef(null)
  const dragging = useRef(false)
  const lastMouse = useRef({ x: 0, y: 0 })

  // Load scans list
  useEffect(() => {
    fetch(`${API}/scans`).then(r => r.json()).then(d => {
      const s = d.scans || []
      setScans(s)
      if (!scanId && s.length) setScanId(s[0].scan_id)
    }).catch(() => {})
  }, [])

  // Load graph data for selected scan
  useEffect(() => {
    if (!scanId) { setLoading(false); return }
    setLoading(true)
    Promise.all([
      fetch(`${API}/scans/${scanId}/attack-graph`).then(r => r.json()),
      fetch(`${API}/scans/${scanId}`).then(r => r.json()),
    ]).then(([graph, state]) => {
      setGraphData(graph)
      setScanState(state)
    }).catch(() => {
      setGraphData(null)
    }).finally(() => setLoading(false))
  }, [scanId])

  // Layout
  const { positioned, layoutEdges, width: gw, height: gh } = useMemo(() => {
    if (!graphData?.nodes?.length) return { positioned: [], layoutEdges: [], width: 600, height: 400 }
    return layoutGraph(graphData.nodes, graphData.edges || [])
  }, [graphData])

  const svgWidth = Math.max(gw || 600, 600)
  const svgHeight = Math.max(gh || 400, 400)

  // Highlight nodes in selected path
  const pathNodeIds = useMemo(() => {
    if (!selectedPath) return new Set()
    return new Set(selectedPath.nodes)
  }, [selectedPath])

  /* ── Pan & Zoom handlers ─────────────────────────────────────────────── */
  const onWheel = useCallback(e => {
    e.preventDefault()
    setZoom(z => Math.min(3, Math.max(0.3, z - e.deltaY * 0.001)))
  }, [])

  const onMouseDown = useCallback(e => {
    dragging.current = true
    lastMouse.current = { x: e.clientX, y: e.clientY }
  }, [])
  const onMouseMove = useCallback(e => {
    if (!dragging.current) return
    setPan(p => ({
      x: p.x + (e.clientX - lastMouse.current.x),
      y: p.y + (e.clientY - lastMouse.current.y),
    }))
    lastMouse.current = { x: e.clientX, y: e.clientY }
  }, [])
  const onMouseUp = useCallback(() => { dragging.current = false }, [])

  const riskSummary = graphData?.risk_summary || {}
  const riskProp = graphData?.risk_propagation || {}
  const paths = graphData?.paths || []

  return (
    <div className="p-6 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Link to="/" className="text-aegis-muted hover:text-white transition-colors">
            <ArrowLeft size={20} />
          </Link>
          <div>
            <h1 className="text-2xl font-display font-bold text-white flex items-center gap-2">
              <Network size={24} className="text-indigo-400" /> Attack Graph
            </h1>
            <p className="text-aegis-muted text-sm mt-0.5">
              AI-powered attack path analysis &amp; risk propagation
            </p>
          </div>
        </div>

        {/* Scan selector */}
        {scans.length > 0 && (
          <select
            className="bg-aegis-surface border border-aegis-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-aegis-accent"
            value={scanId || ''}
            onChange={e => { setScanId(e.target.value); setSelectedPath(null) }}
          >
            <option value="" disabled>Select scan…</option>
            {scans.map(s => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.scan_id} — {s.target_url}
              </option>
            ))}
          </select>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-96 text-aegis-muted">
          <div className="animate-pulse flex items-center gap-2">
            <Network size={20} className="animate-spin" /> Building attack graph…
          </div>
        </div>
      ) : !graphData || !positioned.length ? (
        <div className="flex flex-col items-center justify-center h-96 text-center">
          <Network size={48} className="text-aegis-muted mb-4 opacity-40" />
          <h3 className="text-lg font-semibold text-white mb-2">No Attack Graph Available</h3>
          <p className="text-sm text-aegis-muted max-w-md">
            Run a scan first — the attack graph is generated after vulnerability testing completes.
          </p>
          <Link to="/scan/new" className="mt-4 px-4 py-2 bg-aegis-accent rounded-lg text-white text-sm font-semibold hover:bg-aegis-accent-glow transition-colors">
            Start a Scan
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
          {/* ── Left: Risk summary cards ────────────────────── */}
          <div className="xl:col-span-1 space-y-4">
            {/* Overall Risk */}
            <div className="card p-5">
              <h3 className="text-xs uppercase tracking-wider text-aegis-muted mb-3 flex items-center gap-1.5">
                <Shield size={14} /> Overall Risk
              </h3>
              <div className="flex items-end gap-3 mb-3">
                <span className="text-4xl font-display font-bold" style={{ color: riskColor(riskSummary.overall_risk || 0) }}>
                  {riskSummary.overall_risk || 0}
                </span>
                <span className="text-lg text-aegis-muted font-mono">/ 10</span>
              </div>
              <div className="h-2 bg-aegis-surface rounded-full overflow-hidden mb-2">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${((riskSummary.overall_risk || 0) / 10) * 100}%`,
                    backgroundColor: riskColor(riskSummary.overall_risk || 0),
                  }}
                />
              </div>
              <span className="text-xs font-mono uppercase font-bold tracking-wider"
                style={{ color: riskColor(riskSummary.overall_risk || 0) }}>
                {riskSummary.risk_level || 'N/A'} risk
              </span>
            </div>

            {/* Graph stats */}
            <div className="card p-5 space-y-3">
              <h3 className="text-xs uppercase tracking-wider text-aegis-muted flex items-center gap-1.5">
                <TrendingUp size={14} /> Graph Stats
              </h3>
              {[
                ['Nodes', graphData.node_count || 0],
                ['Edges', graphData.edge_count || 0],
                ['Attack Paths', paths.length],
                ['Critical Paths', riskSummary.critical_paths || 0],
                ['High Paths', riskSummary.high_paths || 0],
                ['Avg Path Risk', riskSummary.avg_path_risk || 0],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center justify-between text-sm">
                  <span className="text-aegis-muted">{k}</span>
                  <span className="font-mono font-bold text-white">{v}</span>
                </div>
              ))}
            </div>

            {/* Risk Propagation */}
            {riskProp.impact_risks?.length > 0 && (
              <div className="card p-5">
                <h3 className="text-xs uppercase tracking-wider text-aegis-muted mb-3 flex items-center gap-1.5">
                  <Zap size={14} /> Risk Propagation — Impacts
                </h3>
                <div className="space-y-2">
                  {riskProp.impact_risks.slice(0, 8).map((imp, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="text-xs text-white font-semibold truncate">{imp.label}</div>
                        <div className="h-1.5 mt-1 bg-aegis-surface rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.min(100, imp.propagated_risk * 100)}%`,
                              backgroundColor: riskColor(imp.propagated_risk * 10),
                            }}
                          />
                        </div>
                      </div>
                      <span className="text-xs font-mono text-aegis-muted w-10 text-right">
                        {(imp.propagated_risk * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ── Center: Interactive graph ───────────────────── */}
          <div className="xl:col-span-3 space-y-4">
            {/* Graph canvas */}
            <div className="card overflow-hidden relative" style={{ minHeight: 500 }}>
              {/* Legend */}
              <div className="absolute top-3 left-3 z-10 bg-aegis-surface/90 backdrop-blur rounded-lg px-3 py-2 border border-aegis-border">
                <div className="flex flex-wrap gap-3 text-xs">
                  {Object.entries(NODE_STYLES).filter(([k]) => k !== 'unknown').map(([key, s]) => (
                    <span key={key} className="flex items-center gap-1">
                      <span className="w-3 h-3 rounded-full" style={{ backgroundColor: s.fill }} />
                      <span className="text-aegis-muted capitalize">{key}</span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Zoom controls */}
              <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
                <button onClick={() => setZoom(z => Math.min(3, z + 0.2))} className="w-8 h-8 bg-aegis-surface border border-aegis-border rounded text-white hover:bg-aegis-card flex items-center justify-center text-lg">+</button>
                <button onClick={() => setZoom(z => Math.max(0.3, z - 0.2))} className="w-8 h-8 bg-aegis-surface border border-aegis-border rounded text-white hover:bg-aegis-card flex items-center justify-center text-lg">−</button>
                <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }} className="w-8 h-8 bg-aegis-surface border border-aegis-border rounded text-aegis-muted hover:bg-aegis-card flex items-center justify-center text-xs">⟲</button>
              </div>

              <svg
                ref={svgRef}
                width="100%"
                height={500}
                viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                className="cursor-grab active:cursor-grabbing"
                onWheel={onWheel}
                onMouseDown={onMouseDown}
                onMouseMove={onMouseMove}
                onMouseUp={onMouseUp}
                onMouseLeave={onMouseUp}
              >
                <defs>
                  <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#475569" />
                  </marker>
                  <marker id="arrowhead-red" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
                  </marker>
                  <marker id="arrowhead-blue" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#60a5fa" />
                  </marker>
                </defs>

                <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                  {/* Edges */}
                  {layoutEdges.map((e, i) => {
                    const eType = e.type || e.edge_type || ''
                    const color = EDGE_COLORS[eType] || '#475569'
                    const isHighlighted = pathNodeIds.size > 0 &&
                      pathNodeIds.has(e.from || e.source) && pathNodeIds.has(e.to || e.target)
                    const opacity = pathNodeIds.size > 0 ? (isHighlighted ? 1 : 0.15) : 0.6

                    // Offset endpoint to avoid overlapping node circle
                    const dx = e.x2 - e.x1, dy = e.y2 - e.y1
                    const len = Math.sqrt(dx * dx + dy * dy) || 1
                    const r = (NODE_STYLES[positioned.find(n => n.id === (e.to || e.target))?.type]?.radius || 20) + 4
                    const x2 = e.x2 - (dx / len) * r
                    const y2 = e.y2 - (dy / len) * r

                    return (
                      <g key={i} opacity={opacity}>
                        <line
                          x1={e.x1} y1={e.y1} x2={x2} y2={y2}
                          stroke={isHighlighted ? '#f59e0b' : color}
                          strokeWidth={isHighlighted ? 2.5 : 1.5}
                          markerEnd={eType === 'exploit' || eType === 'impact' ? 'url(#arrowhead-red)' : 'url(#arrowhead)'}
                        />
                        {e.label && (
                          <text
                            x={(e.x1 + x2) / 2} y={(e.y1 + y2) / 2 - 6}
                            textAnchor="middle"
                            fill="#94a3b8"
                            fontSize={9}
                            className="select-none pointer-events-none"
                          >{e.label}</text>
                        )}
                      </g>
                    )
                  })}

                  {/* Nodes */}
                  {positioned.map(n => {
                    const style = NODE_STYLES[n.type] || NODE_STYLES.unknown
                    const isHovered = hoveredNode === n.id
                    const isInPath = pathNodeIds.size > 0 && pathNodeIds.has(n.id)
                    const dimmed = pathNodeIds.size > 0 && !isInPath
                    const r = style.radius + (isHovered ? 4 : 0)

                    return (
                      <g
                        key={n.id}
                        transform={`translate(${n.x},${n.y})`}
                        onMouseEnter={() => setHoveredNode(n.id)}
                        onMouseLeave={() => setHoveredNode(null)}
                        className="cursor-pointer"
                        opacity={dimmed ? 0.2 : 1}
                      >
                        {/* Glow ring */}
                        {(isHovered || isInPath) && (
                          <circle r={r + 6} fill="none" stroke={isInPath ? '#f59e0b' : style.stroke} strokeWidth={2} opacity={0.5} />
                        )}
                        {/* Main circle */}
                        <circle
                          r={r}
                          fill={n.color || style.fill}
                          stroke={style.stroke}
                          strokeWidth={1.5}
                          className="transition-all duration-150"
                        />
                        {/* Icon */}
                        <text textAnchor="middle" dy="1" fontSize={r * 0.7} className="select-none pointer-events-none">
                          {style.icon}
                        </text>
                        {/* Label below */}
                        <text
                          y={r + 14}
                          textAnchor="middle"
                          fill="#e2e8f0"
                          fontSize={10}
                          fontWeight={isHovered ? 700 : 500}
                          className="select-none pointer-events-none"
                        >
                          {(n.label || n.id).length > 24 ? (n.label || n.id).slice(0, 22) + '…' : (n.label || n.id)}
                        </text>

                        {/* Tooltip */}
                        {isHovered && (
                          <foreignObject x={r + 10} y={-30} width={220} height={90}>
                            <div xmlns="http://www.w3.org/1999/xhtml"
                              className="bg-aegis-surface border border-aegis-border rounded-lg p-2.5 text-xs shadow-xl"
                              style={{ pointerEvents: 'none' }}>
                              <div className="font-bold text-white mb-1">{n.label || n.id}</div>
                              <div className="text-aegis-muted">Type: <span className="text-white capitalize">{n.type}</span></div>
                              {n.severity && <div className="text-aegis-muted">Severity: <span className="text-red-400">{n.severity}</span></div>}
                              {n.risk > 0 && <div className="text-aegis-muted">Risk: <span className="text-amber-400">{n.risk}</span></div>}
                              {n.description && <div className="text-aegis-muted mt-1 truncate">{n.description}</div>}
                            </div>
                          </foreignObject>
                        )}
                      </g>
                    )
                  })}
                </g>
              </svg>
            </div>

            {/* Attack Paths table */}
            <div className="card">
              <div className="p-4 border-b border-aegis-border flex items-center justify-between">
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <Target size={16} className="text-red-400" />
                  Attack Paths
                  <span className="text-xs font-mono text-aegis-muted ml-1">({paths.length})</span>
                </h3>
                {selectedPath && (
                  <button onClick={() => setSelectedPath(null)} className="text-xs text-aegis-accent hover:text-aegis-accent-glow">
                    Clear selection
                  </button>
                )}
              </div>

              {paths.length === 0 ? (
                <div className="p-8 text-center text-aegis-muted text-sm">
                  No attack paths discovered — the target may have good security posture.
                </div>
              ) : (
                <div className="divide-y divide-aegis-border max-h-80 overflow-y-auto">
                  {paths.map((path, i) => {
                    const isSelected = selectedPath === path
                    return (
                      <button
                        key={i}
                        onClick={() => setSelectedPath(isSelected ? null : path)}
                        className={`w-full text-left p-3 hover:bg-aegis-card/40 transition-colors ${isSelected ? 'bg-aegis-accent/10 border-l-2 border-aegis-accent' : ''}`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-mono text-aegis-muted">Path #{i + 1}</span>
                          <span
                            className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                            style={{
                              color: riskColor(path.risk_score),
                              backgroundColor: riskColor(path.risk_score) + '20',
                            }}
                          >
                            Risk {path.risk_score.toFixed(1)}
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-1 text-xs">
                          {path.labels.map((label, j) => (
                            <React.Fragment key={j}>
                              {j > 0 && <ChevronRight size={10} className="text-aegis-muted" />}
                              <span className={`px-1.5 py-0.5 rounded ${
                                j === 0 ? 'bg-indigo-950 text-indigo-300' :
                                j === path.labels.length - 1 ? 'bg-red-950 text-red-300' :
                                'bg-aegis-surface text-aegis-text'
                              }`}>
                                {label.length > 30 ? label.slice(0, 28) + '…' : label}
                              </span>
                            </React.Fragment>
                          ))}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
