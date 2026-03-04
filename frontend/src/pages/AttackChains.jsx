import React, { useState, useEffect, useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  Link2, AlertTriangle, ChevronDown, ChevronRight,
  Shield, Target, Zap, ExternalLink, Activity, Bug, ArrowRight
} from 'lucide-react'
import { PageHeader, SeverityBadge, StatCard, EmptyState } from '../components/shared/index.jsx'

// ── Severity colours for chain cards ────────────────────────────────────────
const SEV_STYLES = {
  CRITICAL: {
    border: 'border-red-700/60',
    bg: 'bg-gradient-to-br from-red-950/60 to-red-900/20',
    badge: 'bg-red-600 text-white',
    glow: 'shadow-red-900/30',
    accent: 'text-red-400',
    bar: 'bg-red-500',
  },
  HIGH: {
    border: 'border-orange-700/50',
    bg: 'bg-gradient-to-br from-orange-950/50 to-orange-900/10',
    badge: 'bg-orange-600 text-white',
    glow: 'shadow-orange-900/20',
    accent: 'text-orange-400',
    bar: 'bg-orange-500',
  },
  MEDIUM: {
    border: 'border-amber-700/40',
    bg: 'bg-gradient-to-br from-amber-950/40 to-amber-900/10',
    badge: 'bg-amber-600 text-white',
    glow: 'shadow-amber-900/15',
    accent: 'text-amber-400',
    bar: 'bg-amber-500',
  },
  LOW: {
    border: 'border-blue-700/30',
    bg: 'bg-gradient-to-br from-blue-950/30 to-blue-900/10',
    badge: 'bg-blue-600 text-white',
    glow: 'shadow-blue-900/10',
    accent: 'text-blue-400',
    bar: 'bg-blue-500',
  },
}

const NODE_ICONS = {
  attacker: '🔴',
  endpoint: '🌐',
  category: '📂',
  vulnerability: '⚠️',
  impact: '💥',
}

// ═════════════════════════════════════════════════════════════════════════════
// Main page component
// ═════════════════════════════════════════════════════════════════════════════

export default function AttackChains() {
  const { scanId: paramScanId } = useParams()
  const navigate = useNavigate()

  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(paramScanId || '')
  const [chainData, setChainData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedChain, setExpandedChain] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('ALL')

  // Fetch scans list
  useEffect(() => {
    fetch('/api/scans')
      .then(r => r.json())
      .then(d => {
        const list = d.scans || []
        setScans(list)
        if (!selectedScan && list.length > 0) {
          const completed = list.filter(s => s.status === 'completed')
          if (completed.length > 0) setSelectedScan(completed[0].scan_id)
        }
      })
      .catch(() => {})
  }, [])

  // Fetch attack chains for selected scan
  useEffect(() => {
    if (!selectedScan) return
    setLoading(true)
    fetch(`/api/scans/${selectedScan}/attack-chains`)
      .then(r => r.json())
      .then(data => { setChainData(data); setLoading(false) })
      .catch(() => { setChainData(null); setLoading(false) })
  }, [selectedScan])

  const stats = chainData?.stats || {}
  const chains = chainData?.chains || []

  const filtered = useMemo(() => {
    if (severityFilter === 'ALL') return chains
    return chains.filter(c => c.severity === severityFilter)
  }, [chains, severityFilter])

  // ── No scans ──────────────────────────────────────────────────────────
  if (scans.length === 0 && !loading) {
    return (
      <div className="p-8">
        <PageHeader
          title="Attack Chain Discovery"
          subtitle="Autonomous multi-step exploitation path analysis"
        />
        <EmptyState
          icon={Link2}
          title="No scans yet"
          description="Run a scan first to discover attack chains."
          action={
            <Link to="/scan/new" className="btn-primary text-sm px-4 py-2 rounded-lg bg-aegis-accent text-white hover:bg-aegis-accent/80">
              Start a Scan
            </Link>
          }
        />
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      {/* Header + scan selector */}
      <div className="flex items-start justify-between">
        <PageHeader
          title="Attack Chain Discovery"
          subtitle="Autonomous multi-step exploitation paths — how attackers chain vulnerabilities into real compromises"
        />
        <select
          value={selectedScan}
          onChange={e => { setSelectedScan(e.target.value); setExpandedChain(null) }}
          className="bg-aegis-surface border border-aegis-border text-aegis-text text-sm rounded-lg px-3 py-2 font-mono"
        >
          <option value="">Select scan…</option>
          {scans.map(s => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.target_url} — {s.status}
            </option>
          ))}
        </select>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="flex items-center gap-3 text-aegis-muted">
            <Activity className="animate-spin" size={20} />
            <span className="font-mono text-sm">Analysing attack chains…</span>
          </div>
        </div>
      )}

      {!loading && chainData && (
        <>
          {/* ── Summary Cards ─────────────────────────────────────────── */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Total Chains" value={stats.total_chains || 0} icon={Link2} color="indigo" />
            <StatCard label="Critical" value={stats.critical || 0} icon={AlertTriangle} color="red" />
            <StatCard label="High" value={stats.high || 0} icon={Zap} color="amber" />
            <StatCard label="Medium" value={stats.medium || 0} icon={Shield} color="green" />
            <StatCard label="Unique CVEs" value={stats.unique_cves || 0} icon={Bug} color="cyan" />
          </div>

          {/* ── Score overview bar ─────────────────────────────────────── */}
          {stats.total_chains > 0 && (
            <div className="card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-aegis-text uppercase tracking-wider">Severity Distribution</h3>
                <span className="font-mono text-xs text-aegis-muted">
                  Max score: <span className="text-white font-bold">{stats.max_score}</span> &middot; Avg: {stats.avg_score} &middot; Avg length: {stats.avg_length} steps
                </span>
              </div>
              <div className="flex h-3 rounded-full overflow-hidden bg-aegis-surface border border-aegis-border">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                  const count = stats[sev.toLowerCase()] || 0
                  if (count === 0) return null
                  const pct = (count / stats.total_chains) * 100
                  return (
                    <div
                      key={sev}
                      className={`${SEV_STYLES[sev].bar} transition-all`}
                      style={{ width: `${pct}%` }}
                      title={`${sev}: ${count}`}
                    />
                  )
                })}
              </div>
              <div className="flex gap-4 text-xs text-aegis-muted">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                  <span key={sev} className="flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${SEV_STYLES[sev].bar}`} />
                    {sev} ({stats[sev.toLowerCase()] || 0})
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ── Filter tabs ───────────────────────────────────────────── */}
          <div className="flex gap-2">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
              const count = sev === 'ALL' ? chains.length : chains.filter(c => c.severity === sev).length
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all border ${
                    severityFilter === sev
                      ? 'bg-aegis-accent/20 text-aegis-accent border-aegis-accent/40'
                      : 'text-aegis-muted border-aegis-border hover:bg-aegis-card hover:text-aegis-text'
                  }`}
                >
                  {sev} ({count})
                </button>
              )
            })}
          </div>

          {/* ── Chain list ─────────────────────────────────────────────── */}
          {filtered.length === 0 ? (
            <EmptyState
              icon={Link2}
              title="No attack chains found"
              description={severityFilter !== 'ALL'
                ? `No ${severityFilter} chains detected. Try a different filter.`
                : 'The scan did not discover any multi-step attack chains.'}
            />
          ) : (
            <div className="space-y-4">
              {filtered.map(chain => (
                <ChainCard
                  key={chain.id}
                  chain={chain}
                  expanded={expandedChain === chain.id}
                  onToggle={() => setExpandedChain(expandedChain === chain.id ? null : chain.id)}
                />
              ))}
            </div>
          )}
        </>
      )}

      {!loading && !chainData && selectedScan && (
        <EmptyState
          icon={Link2}
          title="No chain data available"
          description="The scan may still be running or did not produce attack chain analysis."
        />
      )}
    </div>
  )
}


// ═════════════════════════════════════════════════════════════════════════════
// Chain Card
// ═════════════════════════════════════════════════════════════════════════════

function ChainCard({ chain, expanded, onToggle }) {
  const style = SEV_STYLES[chain.severity] || SEV_STYLES.LOW

  return (
    <div className={`rounded-xl border ${style.border} ${style.bg} overflow-hidden transition-all shadow-lg ${style.glow}`}>
      {/* ── Header ──────────────────────────────────────────────────── */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-4 p-5 hover:bg-white/[0.02] transition-colors text-left"
      >
        {/* Severity badge */}
        <span className={`px-2.5 py-1 rounded-md text-xs font-bold ${style.badge} flex-shrink-0`}>
          {chain.severity}
        </span>

        {/* Chain overview */}
        <div className="flex-1 min-w-0">
          <div className="font-semibold text-aegis-text text-sm">
            Attack Chain #{chain.id}
            <span className="ml-2 text-aegis-muted font-normal">
              — {chain.length} steps, {chain.vulnerabilities.length} vuln{chain.vulnerabilities.length !== 1 ? 's' : ''}, {chain.impacts.length} impact{chain.impacts.length !== 1 ? 's' : ''}
            </span>
          </div>
          {/* Mini path preview */}
          <div className="flex items-center gap-1 mt-1 overflow-hidden">
            {chain.labels.slice(0, 6).map((lbl, i) => (
              <React.Fragment key={i}>
                {i > 0 && <ArrowRight size={10} className="text-aegis-muted/50 flex-shrink-0" />}
                <span className="text-xs text-aegis-muted truncate max-w-[140px]">{lbl}</span>
              </React.Fragment>
            ))}
            {chain.labels.length > 6 && <span className="text-xs text-aegis-muted">…</span>}
          </div>
        </div>

        {/* Score + expand */}
        <div className="flex items-center gap-4 flex-shrink-0">
          <div className="text-right">
            <div className={`text-lg font-display font-bold ${style.accent}`}>{chain.score}</div>
            <div className="text-[10px] text-aegis-muted uppercase tracking-wider">Score</div>
          </div>
          <span className="text-aegis-muted">{expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}</span>
        </div>
      </button>

      {/* ── Expanded detail ────────────────────────────────────────── */}
      {expanded && (
        <div className="border-t border-white/5 p-5 space-y-6 animate-fade-in">
          {/* Chain path visualization */}
          <div>
            <h4 className="text-xs uppercase tracking-wider text-aegis-muted mb-3 font-semibold">Attack Path</h4>
            <div className="relative pl-6">
              {chain.labels.map((label, i) => {
                const nodeId = chain.path[i]
                const nodeType = getNodeType(chain, nodeId)
                const icon = NODE_ICONS[nodeType] || '•'
                const isLast = i === chain.labels.length - 1

                return (
                  <div key={i} className="relative mb-0">
                    {/* Vertical connector line */}
                    {!isLast && (
                      <div className="absolute left-[7px] top-[28px] w-0.5 h-[calc(100%-4px)] bg-gradient-to-b from-aegis-muted/30 to-aegis-muted/10" />
                    )}
                    <div className="flex items-start gap-3 pb-4">
                      <span className="text-base flex-shrink-0 relative z-10 bg-aegis-bg rounded">{icon}</span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-aegis-text">{label}</span>
                          <span className="text-[10px] font-mono text-aegis-muted/60 uppercase">{nodeType}</span>
                        </div>
                        {nodeType === 'vulnerability' && (
                          <VulnDetail chain={chain} nodeId={nodeId} />
                        )}
                        {nodeType === 'impact' && (
                          <ImpactDetail chain={chain} nodeId={nodeId} />
                        )}
                      </div>
                      {!isLast && (
                        <div className="flex-shrink-0 mt-1">
                          <ArrowRight size={12} className={`${style.accent} opacity-50`} />
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* CVE Intelligence */}
          {chain.cve_ids.length > 0 && (
            <div className="p-4 bg-indigo-950/30 border border-indigo-800/30 rounded-lg">
              <h4 className="text-xs uppercase tracking-wider text-indigo-400 mb-2 font-semibold">
                Associated CVEs ({chain.cve_ids.length})
              </h4>
              <div className="flex flex-wrap gap-2">
                {chain.cve_ids.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-indigo-900/40 border border-indigo-700/30 text-xs font-mono text-indigo-400 hover:text-indigo-300 hover:bg-indigo-900/60 transition-colors"
                  >
                    {cve}
                    <ExternalLink size={10} />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-4">
            <MiniStat label="Chain Length" value={`${chain.length} steps`} />
            <MiniStat label="Probability" value={`${(chain.probability * 100).toFixed(1)}%`} />
            <MiniStat label="Endpoints" value={chain.endpoints.length} />
            <MiniStat label="CVEs Linked" value={chain.cve_ids.length} />
          </div>

          {/* Affected endpoints */}
          {chain.endpoints.length > 0 && (
            <div>
              <h4 className="text-xs uppercase tracking-wider text-aegis-muted mb-2 font-semibold">Traversed Endpoints</h4>
              <div className="flex flex-wrap gap-2">
                {chain.endpoints.map((ep, i) => (
                  <span key={i} className="px-2 py-1 bg-aegis-surface border border-aegis-border rounded text-xs font-mono text-aegis-text">
                    {ep.label}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}


// ── Helper sub-components ───────────────────────────────────────────────────

function VulnDetail({ chain, nodeId }) {
  const vuln = chain.vulnerabilities.find(v => v.id === nodeId)
  if (!vuln) return null
  return (
    <div className="mt-1 space-y-1">
      <div className="flex items-center gap-2">
        <SeverityBadge severity={vuln.severity} size="xs" />
        {vuln.cvss_score && (
          <span className="text-[10px] font-mono text-amber-400">
            CVSS {vuln.cvss_score}
          </span>
        )}
        <span className="text-[10px] font-mono text-aegis-muted">
          {(vuln.confidence * 100).toFixed(0)}% conf
        </span>
      </div>
      {vuln.cve_ids?.length > 0 && (
        <div className="flex gap-1.5 flex-wrap">
          {vuln.cve_ids.slice(0, 3).map(cve => (
            <a
              key={cve}
              href={`https://nvd.nist.gov/vuln/detail/${cve}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] font-mono text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
            >
              {cve}
            </a>
          ))}
        </div>
      )}
    </div>
  )
}

function ImpactDetail({ chain, nodeId }) {
  const impact = chain.impacts.find(i => i.id === nodeId)
  if (!impact) return null
  return (
    <div className="mt-1">
      {impact.description && (
        <p className="text-xs text-red-400/80">{impact.description}</p>
      )}
      <span className="text-[10px] font-mono text-aegis-muted">
        Impact severity: {impact.severity}
      </span>
    </div>
  )
}

function MiniStat({ label, value }) {
  return (
    <div className="bg-aegis-surface/50 border border-aegis-border rounded-lg p-3 text-center">
      <div className="text-lg font-display font-bold text-white">{value}</div>
      <div className="text-[10px] text-aegis-muted uppercase tracking-wider mt-0.5">{label}</div>
    </div>
  )
}

function getNodeType(chain, nodeId) {
  if (chain.vulnerabilities.some(v => v.id === nodeId)) return 'vulnerability'
  if (chain.impacts.some(i => i.id === nodeId)) return 'impact'
  if (chain.endpoints.some(e => e.id === nodeId)) return 'endpoint'
  if (nodeId === 'attacker') return 'attacker'
  return 'category'
}
