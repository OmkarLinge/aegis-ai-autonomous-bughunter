import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Bug, Filter, Search, ArrowLeft, ExternalLink } from 'lucide-react'
import { SeverityBadge, VulnRow, EmptyState, PageHeader } from '../components/shared/index.jsx'

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

export default function Vulnerabilities() {
  const { scanId } = useParams()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(scanId || '')
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(d => {
      const s = d.scans || []
      setScans(s)
      if (!selectedScan && s.length > 0) setSelectedScan(s[0].scan_id)
    })
  }, [])

  useEffect(() => {
    if (!selectedScan) return
    setLoading(true)
    fetch(`/api/scans/${selectedScan}/vulnerabilities`)
      .then(r => r.json())
      .then(d => {
        const sorted = (d.vulnerabilities || []).sort(
          (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
        )
        setVulns(sorted)
      })
      .finally(() => setLoading(false))
  }, [selectedScan])

  const filtered = vulns
    .filter(v => filter === 'ALL' || v.severity === filter)
    .filter(v =>
      !search ||
      v.title?.toLowerCase().includes(search.toLowerCase()) ||
      v.url?.toLowerCase().includes(search.toLowerCase()) ||
      v.vuln_type?.toLowerCase().includes(search.toLowerCase())
    )

  const counts = {
    ALL: vulns.length,
    CRITICAL: vulns.filter(v => v.severity === 'CRITICAL').length,
    HIGH: vulns.filter(v => v.severity === 'HIGH').length,
    MEDIUM: vulns.filter(v => v.severity === 'MEDIUM').length,
    LOW: vulns.filter(v => v.severity === 'LOW').length,
  }

  const filterColors = {
    ALL: 'bg-slate-800 text-slate-300 border-slate-600',
    CRITICAL: 'bg-red-950 text-red-400 border-red-800',
    HIGH: 'bg-red-900/40 text-red-400 border-red-700',
    MEDIUM: 'bg-amber-900/40 text-amber-400 border-amber-700',
    LOW: 'bg-emerald-900/40 text-emerald-400 border-emerald-700',
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <PageHeader
        title="Vulnerability Explorer"
        subtitle="Detailed findings from all security scans"
        action={
          <Link
            to="/reports"
            className="flex items-center gap-2 px-4 py-2 text-sm bg-aegis-card border border-aegis-border hover:border-aegis-accent text-aegis-text rounded-lg transition-colors"
          >
            <ExternalLink size={14} />
            Generate Report
          </Link>
        }
      />

      {/* Scan selector */}
      <div className="card p-4 mb-5">
        <div className="flex items-center gap-3">
          <label className="text-sm text-aegis-muted flex-shrink-0">Scan:</label>
          <select
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
            className="flex-1 bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-sm text-aegis-text focus:outline-none focus:border-aegis-accent"
          >
            <option value="">— Select a scan —</option>
            {scans.map(s => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.target_url} ({s.scan_id}) · {s.vulnerability_count} vulns
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="flex gap-2">
          {Object.entries(counts).map(([sev, count]) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`text-xs font-mono px-3 py-1.5 rounded border transition-all ${
                filter === sev
                  ? (filterColors[sev] + ' ring-1 ring-offset-1 ring-offset-aegis-bg ring-current')
                  : 'bg-aegis-surface text-aegis-muted border-aegis-border hover:border-aegis-muted'
              }`}
            >
              {sev} ({count})
            </button>
          ))}
        </div>
        <div className="flex-1 relative min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-aegis-muted" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="w-full pl-9 pr-4 py-1.5 bg-aegis-bg border border-aegis-border rounded-lg text-sm text-aegis-text placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent"
          />
        </div>
      </div>

      {/* Vulnerability list */}
      {loading ? (
        <div className="space-y-3">
          {[1,2,3].map(i => (
            <div key={i} className="h-16 skeleton rounded-lg" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Bug}
          title={vulns.length === 0 ? "No vulnerabilities found" : "No results match your filter"}
          description={
            vulns.length === 0
              ? "Select a completed scan to view vulnerability findings"
              : "Try adjusting your search or filter criteria"
          }
        />
      ) : (
        <div className="space-y-2">
          {filtered.map((vuln, i) => (
            <VulnRow
              key={vuln.id || i}
              vuln={vuln}
              expanded={expandedId === (vuln.id || i)}
              onToggle={() => setExpandedId(expandedId === (vuln.id || i) ? null : (vuln.id || i))}
            />
          ))}
        </div>
      )}

      {filtered.length > 0 && (
        <div className="mt-4 text-xs text-aegis-muted text-center font-mono">
          Showing {filtered.length} of {vulns.length} vulnerabilities
        </div>
      )}
    </div>
  )
}
