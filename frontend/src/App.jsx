import React, { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom'
import {
  Shield, Activity, Bug, FileText, Settings,
  Terminal, ChevronRight, Wifi, WifiOff, BarChart2, Network, Link2
} from 'lucide-react'
import Dashboard from './pages/Dashboard.jsx'
import LiveScan from './pages/LiveScan.jsx'
import Vulnerabilities from './pages/Vulnerabilities.jsx'
import Reports from './pages/Reports.jsx'
import NewScan from './pages/NewScan.jsx'
import AttackGraph from './pages/AttackGraph.jsx'
import AttackChains from './pages/AttackChains.jsx'

export default function App() {
  const [apiStatus, setApiStatus] = useState('checking')

  useEffect(() => {
    fetch('/api/health')
      .then(r => r.ok ? setApiStatus('online') : setApiStatus('offline'))
      .catch(() => setApiStatus('offline'))
  }, [])

  const navItems = [
    { to: '/', icon: BarChart2, label: 'Dashboard', exact: true },
    { to: '/scan/new', icon: Shield, label: 'New Scan' },
    { to: '/live', icon: Activity, label: 'Live Monitor' },
    { to: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
    { to: '/attack-graph', icon: Network, label: 'Attack Graph' },
    { to: '/attack-chains', icon: Link2, label: 'Attack Chains' },
    { to: '/reports', icon: FileText, label: 'Reports' },
  ]

  return (
    <Router>
      <div className="flex h-screen overflow-hidden bg-aegis-bg">
        {/* Sidebar */}
        <aside className="w-64 flex-shrink-0 bg-aegis-surface border-r border-aegis-border flex flex-col">
          {/* Logo */}
          <div className="p-5 border-b border-aegis-border">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="w-10 h-10 bg-aegis-accent rounded-xl flex items-center justify-center shadow-lg shadow-aegis-accent/30">
                  <Shield size={20} className="text-white" />
                </div>
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-aegis-green rounded-full border-2 border-aegis-surface" />
              </div>
              <div>
                <div className="font-display font-bold text-white text-base tracking-wide">AEGIS AI</div>
                <div className="text-xs text-aegis-muted font-mono">Bug Hunter v1.0</div>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-1">
            {navItems.map(({ to, icon: Icon, label, exact }) => (
              <NavLink
                key={to}
                to={to}
                end={exact}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                    isActive
                      ? 'bg-aegis-accent/20 text-aegis-accent-glow border border-aegis-accent/30'
                      : 'text-aegis-muted hover:text-aegis-text hover:bg-aegis-card'
                  }`
                }
              >
                <Icon size={16} />
                <span>{label}</span>
                <ChevronRight
                  size={12}
                  className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity"
                />
              </NavLink>
            ))}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t border-aegis-border">
            <div className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg ${
              apiStatus === 'online'
                ? 'bg-emerald-950 text-emerald-400'
                : apiStatus === 'offline'
                ? 'bg-red-950 text-red-400'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {apiStatus === 'online' ? <Wifi size={12} /> : <WifiOff size={12} />}
              <span className="font-mono">
                API {apiStatus === 'checking' ? '...' : apiStatus.toUpperCase()}
              </span>
            </div>
            <div className="mt-2 px-3 py-2 text-xs text-aegis-muted/60 font-mono leading-relaxed">
              ⚠️ Authorized scanning only
            </div>
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-auto scan-grid">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/live" element={<LiveScan />} />
            <Route path="/live/:scanId" element={<LiveScan />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/vulnerabilities/:scanId" element={<Vulnerabilities />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
            <Route path="/attack-graph/:scanId" element={<AttackGraph />} />
            <Route path="/attack-chains" element={<AttackChains />} />
            <Route path="/attack-chains/:scanId" element={<AttackChains />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:scanId" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}
