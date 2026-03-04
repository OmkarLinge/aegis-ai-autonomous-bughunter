// Shared UI components for Aegis AI dashboard

import React from 'react'

// ── Severity Badge ──────────────────────────────────────────────────────────
export function SeverityBadge({ severity, size = 'sm' }) {
  const classes = {
    CRITICAL: 'bg-red-950 text-red-400 border-red-800',
    HIGH: 'bg-red-900/40 text-red-400 border-red-700',
    MEDIUM: 'bg-amber-900/40 text-amber-400 border-amber-700',
    LOW: 'bg-emerald-900/40 text-emerald-400 border-emerald-700',
    INFO: 'bg-slate-800 text-slate-400 border-slate-600',
  }
  const sizeClasses = {
    xs: 'text-xs px-1.5 py-0.5',
    sm: 'text-xs px-2 py-1',
    md: 'text-sm px-2.5 py-1',
  }
  return (
    <span className={`inline-flex items-center font-mono font-bold border rounded ${classes[severity] || classes.INFO} ${sizeClasses[size]}`}>
      {severity}
    </span>
  )
}

// ── Status Badge ─────────────────────────────────────────────────────────────
export function StatusBadge({ status }) {
  const map = {
    pending: 'bg-slate-800 text-slate-300 border-slate-600',
    running: 'bg-blue-950 text-blue-400 border-blue-700',
    completed: 'bg-emerald-950 text-emerald-400 border-emerald-700',
    failed: 'bg-red-950 text-red-400 border-red-700',
    cancelled: 'bg-slate-800 text-slate-400 border-slate-600',
  }
  const dots = {
    running: 'bg-blue-400 animate-pulse',
    completed: 'bg-emerald-400',
    failed: 'bg-red-400',
    pending: 'bg-slate-400',
    cancelled: 'bg-slate-400',
  }
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-mono px-2 py-1 rounded border ${map[status] || map.pending}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dots[status] || 'bg-slate-400'}`} />
      {status?.toUpperCase()}
    </span>
  )
}

// ── Stat Card ────────────────────────────────────────────────────────────────
export function StatCard({ label, value, icon: Icon, color = 'indigo', trend }) {
  const colorMap = {
    indigo: 'text-indigo-400 bg-indigo-950/50 border-indigo-800',
    red: 'text-red-400 bg-red-950/50 border-red-800',
    amber: 'text-amber-400 bg-amber-950/50 border-amber-800',
    green: 'text-emerald-400 bg-emerald-950/50 border-emerald-800',
    cyan: 'text-cyan-400 bg-cyan-950/50 border-cyan-800',
  }
  return (
    <div className="card p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-aegis-muted text-xs font-medium uppercase tracking-wider mb-2">{label}</p>
          <p className="text-3xl font-display font-bold text-white">{value}</p>
          {trend && <p className="text-xs text-aegis-muted mt-1">{trend}</p>}
        </div>
        {Icon && (
          <div className={`p-3 rounded-xl border ${colorMap[color]}`}>
            <Icon size={20} />
          </div>
        )}
      </div>
    </div>
  )
}

// ── Progress Bar ─────────────────────────────────────────────────────────────
export function ProgressBar({ value, color = 'indigo', label, showPercent = true }) {
  const colorMap = {
    indigo: 'bg-indigo-500',
    red: 'bg-red-500',
    amber: 'bg-amber-500',
    green: 'bg-emerald-500',
    cyan: 'bg-cyan-500',
  }
  return (
    <div>
      {(label || showPercent) && (
        <div className="flex justify-between text-xs text-aegis-muted mb-1.5">
          {label && <span>{label}</span>}
          {showPercent && <span className="font-mono">{value}%</span>}
        </div>
      )}
      <div className="h-1.5 bg-aegis-surface rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${colorMap[color]}`}
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      </div>
    </div>
  )
}

// ── Terminal Log ─────────────────────────────────────────────────────────────
export function TerminalLog({ logs, maxHeight = '320px' }) {
  const agentColors = {
    RECON: 'text-cyan-400',
    ENDPOINT: 'text-blue-400',
    EXPLOIT: 'text-red-400',
    CLASSIFIER: 'text-purple-400',
    ANOMALY: 'text-yellow-400',
    STRATEGY: 'text-emerald-400',
    REPORT: 'text-white',
    ORCHESTRATOR: 'text-indigo-400',
    SYSTEM: 'text-slate-400',
  }
  const levelColors = {
    INFO: 'text-slate-400',
    WARNING: 'text-amber-400',
    ERROR: 'text-red-400',
    SUCCESS: 'text-emerald-400',
  }
  const ref = React.useRef(null)
  React.useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [logs])

  return (
    <div
      ref={ref}
      className="bg-black/60 rounded-lg border border-aegis-border font-mono text-xs overflow-y-auto"
      style={{ maxHeight }}
    >
      <div className="p-3 space-y-1">
        {logs.length === 0 && (
          <div className="text-aegis-muted py-4 text-center">
            Waiting for scan activity...
          </div>
        )}
        {logs.map((log, i) => (
          <div key={i} className="flex gap-2 leading-relaxed">
            <span className="text-slate-600 flex-shrink-0">
              {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '--:--:--'}
            </span>
            <span className={`flex-shrink-0 ${agentColors[log.agent] || 'text-slate-400'}`}>
              [{log.agent || 'SYS'}]
            </span>
            <span className="text-slate-300">{log.message}</span>
          </div>
        ))}
        <div className="terminal-cursor text-emerald-400">&nbsp;</div>
      </div>
    </div>
  )
}

// ── Empty State ──────────────────────────────────────────────────────────────
export function EmptyState({ icon: Icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      {Icon && (
        <div className="w-16 h-16 bg-aegis-surface rounded-2xl flex items-center justify-center mb-4 border border-aegis-border">
          <Icon size={28} className="text-aegis-muted" />
        </div>
      )}
      <h3 className="text-lg font-semibold text-aegis-text mb-2">{title}</h3>
      {description && <p className="text-sm text-aegis-muted max-w-sm">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

// ── Page Header ──────────────────────────────────────────────────────────────
export function PageHeader({ title, subtitle, action }) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white">{title}</h1>
        {subtitle && <p className="text-sm text-aegis-muted mt-1">{subtitle}</p>}
      </div>
      {action && <div>{action}</div>}
    </div>
  )
}

// ── Vulnerability Row ─────────────────────────────────────────────────────────
export function VulnRow({ vuln, expanded, onToggle }) {
  return (
    <div className={`border border-aegis-border rounded-lg overflow-hidden transition-all ${expanded ? 'shadow-lg shadow-red-950/20' : ''}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-4 p-4 hover:bg-aegis-card/50 transition-colors text-left"
      >
        <SeverityBadge severity={vuln.severity} />
        <div className="flex-1 min-w-0">
          <div className="font-semibold text-aegis-text text-sm truncate">{vuln.title}</div>
          <div className="text-xs text-aegis-muted font-mono truncate">{vuln.url}</div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {vuln.cwe_id && (
            <span className="text-xs font-mono text-aegis-muted">{vuln.cwe_id}</span>
          )}
          <span className="text-xs text-aegis-muted font-mono">
            {(vuln.confidence * 100).toFixed(0)}% conf
          </span>
          <span className="text-aegis-muted">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-aegis-border p-4 space-y-4 animate-fade-in">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-aegis-muted text-xs uppercase tracking-wider">URL</span>
              <p className="font-mono text-aegis-text text-xs mt-1 break-all">{vuln.url}</p>
            </div>
            <div>
              <span className="text-aegis-muted text-xs uppercase tracking-wider">Parameter</span>
              <p className="font-mono text-aegis-text text-xs mt-1">{vuln.parameter || 'N/A'}</p>
            </div>
            {vuln.payload && (
              <div className="col-span-2">
                <span className="text-aegis-muted text-xs uppercase tracking-wider">Payload</span>
                <pre className="mt-1 p-2 bg-black/60 rounded text-xs font-mono text-amber-400 overflow-x-auto">
                  {vuln.payload}
                </pre>
              </div>
            )}
          </div>

          <div>
            <h4 className="text-xs uppercase tracking-wider text-aegis-muted mb-1">Description</h4>
            <p className="text-sm text-aegis-text leading-relaxed">{vuln.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs uppercase tracking-wider text-red-400 mb-1">Impact</h4>
              <p className="text-sm text-aegis-muted">{vuln.impact}</p>
            </div>
            <div>
              <h4 className="text-xs uppercase tracking-wider text-emerald-400 mb-1">Remediation</h4>
              <p className="text-sm text-aegis-muted">{vuln.remediation}</p>
            </div>
          </div>

          {vuln.evidence && (
            <div className="p-3 bg-amber-950/30 border border-amber-800/30 rounded-lg">
              <h4 className="text-xs uppercase tracking-wider text-amber-400 mb-1">Evidence</h4>
              <p className="text-xs font-mono text-amber-300">{vuln.evidence}</p>
            </div>
          )}

          <div className="flex gap-4 text-xs text-aegis-muted font-mono">
            <span>ML: {vuln.ml_prediction?.replace('_', ' ') || 'N/A'}</span>
            <span>Conf: {((vuln.ml_confidence || 0) * 100).toFixed(0)}%</span>
            <span>Anomaly: {(vuln.anomaly_score || 0).toFixed(2)}</span>
          </div>
        </div>
      )}
    </div>
  )
}
