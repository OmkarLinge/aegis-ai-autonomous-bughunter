import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield, Bug, Globe, Clock, TrendingUp, AlertTriangle,
  Activity, ArrowRight, Plus, ChevronRight
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import { StatCard, StatusBadge, SeverityBadge, ProgressBar, PageHeader } from '../components/shared/index.jsx'

const API = '/api'

const SEVERITY_COLORS = {
  CRITICAL: '#7f1d1d',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [statsRes, scansRes] = await Promise.all([
          fetch(`${API}/stats`).then(r => r.json()),
          fetch(`${API}/scans`).then(r => r.json()),
        ])
        setStats(statsRes)
        setScans(scansRes.scans || [])
      } catch (e) {
        console.error('Failed to load dashboard:', e)
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [])

  const severityData = stats ? [
    { name: 'Critical', value: stats.severity_breakdown?.critical || 0, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: stats.severity_breakdown?.high || 0, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: stats.severity_breakdown?.medium || 0, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: stats.severity_breakdown?.low || 0, color: SEVERITY_COLORS.LOW },
  ] : []

  // Build scan timeline data
  const timelineData = scans.slice(-10).map((s, i) => ({
    name: `Scan ${i + 1}`,
    endpoints: s.endpoint_count,
    vulns: s.vulnerability_count,
  }))

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold text-white">
            Security Dashboard
          </h1>
          <p className="text-aegis-muted text-sm mt-1">
            Autonomous AI-powered vulnerability intelligence
          </p>
        </div>
        <Link
          to="/scan/new"
          className="flex items-center gap-2 px-5 py-2.5 bg-aegis-accent hover:bg-aegis-accent-glow rounded-xl text-white font-semibold text-sm transition-all shadow-lg shadow-aegis-accent/25"
        >
          <Plus size={16} />
          New Scan
        </Link>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Total Scans"
          value={stats?.total_scans || 0}
          icon={Shield}
          color="indigo"
          trend={`${stats?.completed_scans || 0} completed`}
        />
        <StatCard
          label="Vulnerabilities"
          value={stats?.total_vulnerabilities || 0}
          icon={Bug}
          color="red"
          trend={`${stats?.severity_breakdown?.critical || 0} critical`}
        />
        <StatCard
          label="Endpoints Scanned"
          value={stats?.total_endpoints || 0}
          icon={Globe}
          color="cyan"
        />
        <StatCard
          label="Active Scans"
          value={stats?.running_scans || 0}
          icon={Activity}
          color="green"
          trend="Running now"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Severity Distribution */}
        <div className="card p-5">
          <h3 className="font-semibold text-white mb-4">Severity Distribution</h3>
          {severityData.some(d => d.value > 0) ? (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width={120} height={120}>
                <PieChart>
                  <Pie
                    data={severityData.filter(d => d.value > 0)}
                    cx="50%" cy="50%"
                    innerRadius={35} outerRadius={55}
                    dataKey="value"
                  >
                    {severityData.filter(d => d.value > 0).map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 flex-1">
                {severityData.map(d => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                      <span className="text-aegis-muted">{d.name}</span>
                    </div>
                    <span className="font-mono text-aegis-text font-bold">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-32 flex items-center justify-center text-aegis-muted text-sm">
              No vulnerability data yet
            </div>
          )}
        </div>

        {/* Scan Timeline */}
        <div className="card p-5 col-span-2">
          <h3 className="font-semibold text-white mb-4">Scan History</h3>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={timelineData} barSize={20}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="endpoints" fill="#4f46e5" name="Endpoints" radius={[3, 3, 0, 0]} />
                <Bar dataKey="vulns" fill="#ef4444" name="Vulnerabilities" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-32 flex items-center justify-center text-aegis-muted text-sm">
              Run scans to see history
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="p-5 border-b border-aegis-border flex items-center justify-between">
          <h3 className="font-semibold text-white">Recent Scans</h3>
          <Link to="/live" className="text-xs text-aegis-accent hover:text-aegis-accent-glow flex items-center gap-1">
            View all <ArrowRight size={12} />
          </Link>
        </div>
        <div className="divide-y divide-aegis-border">
          {loading ? (
            <div className="p-8 text-center text-aegis-muted">Loading...</div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center">
              <Shield size={32} className="mx-auto text-aegis-muted mb-3 opacity-40" />
              <p className="text-aegis-muted text-sm">No scans yet</p>
              <Link
                to="/scan/new"
                className="inline-flex items-center gap-1.5 mt-3 text-sm text-aegis-accent hover:text-aegis-accent-glow"
              >
                Start your first scan <ArrowRight size={12} />
              </Link>
            </div>
          ) : (
            scans.slice(0, 6).map(scan => (
              <div key={scan.scan_id} className="flex items-center gap-4 p-4 hover:bg-aegis-card/30 transition-colors">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm text-white font-semibold truncate">
                      {scan.target_url}
                    </span>
                    <StatusBadge status={scan.status} />
                  </div>
                  <div className="text-xs text-aegis-muted font-mono">
                    ID: {scan.scan_id} · {scan.endpoint_count} endpoints · {scan.vulnerability_count} vulns
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {scan.severity_summary?.critical > 0 && (
                    <SeverityBadge severity="CRITICAL" size="xs" />
                  )}
                  {scan.severity_summary?.high > 0 && (
                    <SeverityBadge severity="HIGH" size="xs" />
                  )}
                  {scan.status === 'running' && (
                    <ProgressBar value={scan.progress || 0} color="indigo" showPercent={false} />
                  )}
                  <Link
                    to={`/live/${scan.scan_id}`}
                    className="text-aegis-muted hover:text-aegis-accent transition-colors"
                  >
                    <ChevronRight size={16} />
                  </Link>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="mt-6 p-4 bg-amber-950/20 border border-amber-800/30 rounded-xl">
        <div className="flex items-start gap-3">
          <AlertTriangle size={16} className="text-amber-400 mt-0.5 flex-shrink-0" />
          <p className="text-xs text-amber-300/80 leading-relaxed">
            <strong className="text-amber-400">Authorized Use Only:</strong> Aegis AI is for
            educational purposes and authorized penetration testing only.
            Only scan systems you own or have explicit written permission to test.
            Unauthorized scanning is illegal under computer fraud laws.
          </p>
        </div>
      </div>
    </div>
  )
}
