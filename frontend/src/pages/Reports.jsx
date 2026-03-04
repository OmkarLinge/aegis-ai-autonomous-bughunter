import React, { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  FileText, Download, Shield, AlertTriangle, CheckCircle,
  Globe, Clock, BarChart, ExternalLink, Share2
} from 'lucide-react'
import { StatusBadge, SeverityBadge, EmptyState, PageHeader } from '../components/shared/index.jsx'

// ── Simple Attack Graph using SVG ────────────────────────────────────────────
function AttackGraph({ graph }) {
  if (!graph?.nodes?.length) {
    return (
      <div className="h-48 flex items-center justify-center text-aegis-muted text-sm">
        Attack graph will appear after scan completes
      </div>
    )
  }

  const nodes = graph.nodes || []
  const edges = graph.edges || []

  // Layout: root in center, others in circle
  const cx = 300, cy = 200, r = 140
  const nonRoot = nodes.filter(n => n.id !== 'target')
  const rootNode = nodes.find(n => n.id === 'target')

  const positioned = {
    target: { x: cx, y: cy, ...rootNode },
  }
  nonRoot.forEach((n, i) => {
    const angle = (i / nonRoot.length) * 2 * Math.PI - Math.PI / 2
    positioned[n.id] = {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      ...n,
    }
  })

  const nodeColor = (n) => {
    if (n.type === 'root') return '#4f46e5'
    if (n.type === 'vulnerability') {
      const c = { CRITICAL: '#7f1d1d', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#10b981' }
      return c[n.severity] || '#6b7280'
    }
    if (n.type === 'impact') return '#ef4444'
    return n.color || '#334155'
  }

  return (
    <svg viewBox="0 0 600 400" className="w-full max-h-80">
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L9,3 z" fill="#475569" />
        </marker>
      </defs>
      {/* Edges */}
      {edges.map((edge, i) => {
        const src = positioned[edge.from || edge.source]
        const tgt = positioned[edge.to || edge.target]
        if (!src || !tgt) return null
        return (
          <g key={i}>
            <line
              x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
              stroke={edge.type === 'exploit' ? '#ef444460' : edge.type === 'impact' ? '#ef444440' : '#33415560'}
              strokeWidth={edge.type === 'exploit' ? 2 : 1}
              markerEnd="url(#arrow)"
              strokeDasharray={edge.type === 'discovery' ? '4,4' : 'none'}
            />
          </g>
        )
      })}
      {/* Nodes */}
      {Object.values(positioned).map((node) => (
        <g key={node.id} transform={`translate(${node.x},${node.y})`}>
          <circle
            r={node.type === 'root' ? 22 : node.type === 'vulnerability' ? 16 : 14}
            fill={nodeColor(node)}
            fillOpacity={0.9}
            stroke={nodeColor(node)}
            strokeWidth={2}
            strokeOpacity={0.5}
          />
          <text
            textAnchor="middle"
            dominantBaseline="middle"
            fill="white"
            fontSize={node.type === 'root' ? 9 : 8}
            fontFamily="monospace"
            dy={node.type === 'root' ? 0 : 0}
          >
            {node.label?.slice(0, 12)}
          </text>
          <text
            textAnchor="middle"
            y={node.type === 'root' ? 32 : 22}
            fill="#94a3b8"
            fontSize={7}
            fontFamily="monospace"
          >
            {node.type !== 'root' ? node.id?.slice(0, 15) : ''}
          </text>
        </g>
      ))}
    </svg>
  )
}

// ── Report Card ───────────────────────────────────────────────────────────────
function ReportCard({ scan }) {
  const [attackGraph, setAttackGraph] = useState(null)
  const [showGraph, setShowGraph] = useState(false)
  const [downloading, setDownloading] = useState({})

  const vulns = scan.vulnerabilities || []
  const sevCounts = {
    CRITICAL: vulns.filter(v => v.severity === 'CRITICAL').length,
    HIGH: vulns.filter(v => v.severity === 'HIGH').length,
    MEDIUM: vulns.filter(v => v.severity === 'MEDIUM').length,
    LOW: vulns.filter(v => v.severity === 'LOW').length,
  }

  const riskRating = sevCounts.CRITICAL > 0 ? 'CRITICAL'
    : sevCounts.HIGH > 0 ? 'HIGH'
    : sevCounts.MEDIUM > 0 ? 'MEDIUM'
    : sevCounts.LOW > 0 ? 'LOW'
    : 'CLEAN'

  const riskColor = {
    CRITICAL: 'text-red-500', HIGH: 'text-red-400',
    MEDIUM: 'text-amber-400', LOW: 'text-emerald-400', CLEAN: 'text-emerald-400'
  }[riskRating]

  const loadGraph = async () => {
    if (!attackGraph) {
      const res = await fetch(`/api/scans/${scan.scan_id}/attack-graph`)
      if (res.ok) setAttackGraph(await res.json())
    }
    setShowGraph(s => !s)
  }

  const download = async (format) => {
    setDownloading(d => ({ ...d, [format]: true }))
    try {
      const res = await fetch(`/api/scans/${scan.scan_id}/report/${format}`)
      if (!res.ok) throw new Error('Report not available')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `aegis_report_${scan.scan_id}.${format === 'markdown' ? 'md' : format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert(e.message)
    } finally {
      setDownloading(d => ({ ...d, [format]: false }))
    }
  }

  return (
    <div className="card overflow-hidden">
      {/* Header */}
      <div className="p-5 border-b border-aegis-border">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <StatusBadge status={scan.status} />
              <span className="font-mono text-xs text-aegis-muted">{scan.scan_id}</span>
            </div>
            <h3 className="font-semibold text-white text-base">{scan.target_url}</h3>
            <p className="text-xs text-aegis-muted mt-1">
              {new Date(scan.started_at).toLocaleString()}
              {scan.duration_seconds && ` · ${scan.duration_seconds.toFixed(1)}s`}
            </p>
          </div>
          <div className="text-right">
            <div className={`text-2xl font-display font-bold ${riskColor}`}>{riskRating}</div>
            <div className="text-xs text-aegis-muted">Risk Rating</div>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 divide-x divide-aegis-border border-b border-aegis-border">
        {Object.entries(sevCounts).map(([sev, count]) => (
          <div key={sev} className="p-3 text-center">
            <div className={`text-xl font-bold ${
              sev === 'CRITICAL' ? 'text-red-500' :
              sev === 'HIGH' ? 'text-red-400' :
              sev === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'
            }`}>{count}</div>
            <div className="text-xs text-aegis-muted">{sev}</div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="p-4">
        <div className="flex flex-wrap gap-2 mb-3">
          {scan.status === 'completed' ? (
            <>
              {['pdf', 'json', 'markdown'].map(fmt => (
                <button
                  key={fmt}
                  onClick={() => download(fmt)}
                  disabled={downloading[fmt]}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-aegis-surface border border-aegis-border hover:border-aegis-accent text-aegis-text rounded-lg transition-all"
                >
                  {downloading[fmt] ? (
                    <div className="w-3 h-3 border border-aegis-muted border-t-white rounded-full animate-spin" />
                  ) : (
                    <Download size={12} />
                  )}
                  {fmt.toUpperCase()}
                </button>
              ))}
              <button
                onClick={loadGraph}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-indigo-950/40 border border-indigo-800 hover:border-indigo-600 text-indigo-400 rounded-lg transition-all"
              >
                <BarChart size={12} />
                {showGraph ? 'Hide Graph' : 'Attack Graph'}
              </button>
            </>
          ) : (
            <span className="text-xs text-aegis-muted italic">
              Reports available after scan completes
            </span>
          )}
        </div>

        {/* Attack graph */}
        {showGraph && (
          <div className="mt-3 p-3 bg-aegis-bg rounded-lg border border-aegis-border">
            <h4 className="text-xs font-semibold text-aegis-muted uppercase tracking-wider mb-3">
              Attack Graph
            </h4>
            <AttackGraph graph={attackGraph || scan.attack_graph} />
          </div>
        )}

        {/* Technologies */}
        {scan.technologies?.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {scan.technologies.map(t => (
              <span key={t} className="text-xs px-2 py-0.5 bg-aegis-surface border border-aegis-border rounded text-aegis-muted">
                {t}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Reports Page ──────────────────────────────────────────────────────────────
export default function Reports() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      const res = await fetch('/api/scans')
      const data = await res.json()
      // Load full scan data for reports
      const fullScans = await Promise.all(
        (data.scans || []).map(s =>
          fetch(`/api/scans/${s.scan_id}`).then(r => r.json()).catch(() => s)
        )
      )
      setScans(fullScans)
      setLoading(false)
    }
    load()
    const iv = setInterval(load, 8000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <PageHeader
        title="Security Reports"
        subtitle="Professional security assessment reports for all scans"
        action={
          <Link
            to="/scan/new"
            className="flex items-center gap-2 px-4 py-2 text-sm bg-aegis-accent hover:bg-aegis-accent-glow text-white rounded-lg transition-colors"
          >
            New Scan
          </Link>
        }
      />

      {loading ? (
        <div className="space-y-4">
          {[1,2].map(i => <div key={i} className="h-48 skeleton rounded-xl" />)}
        </div>
      ) : scans.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No reports yet"
          description="Complete a security scan to generate downloadable PDF, JSON, and Markdown reports"
          action={
            <Link to="/scan/new" className="px-4 py-2 bg-aegis-accent text-white rounded-lg text-sm">
              Start First Scan
            </Link>
          }
        />
      ) : (
        <div className="space-y-4">
          {scans.map(scan => (
            <ReportCard key={scan.scan_id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  )
}
