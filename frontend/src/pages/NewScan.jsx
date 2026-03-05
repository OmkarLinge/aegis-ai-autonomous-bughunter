import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Lock, Target, Zap, AlertTriangle,
  CheckCircle, ChevronRight, Info, Play, LogIn, Key, Cookie
} from 'lucide-react'

const AUTH_TYPES = [
  { id: 'none', label: 'No Authentication', desc: 'Scan public-facing pages only', icon: '🌐' },
  { id: 'form', label: 'Form Login', desc: 'Automate login via username/password form', icon: '📝' },
  { id: 'jwt', label: 'JWT / Bearer Token', desc: 'Inject an existing JWT or API token', icon: '🔑' },
  { id: 'cookie', label: 'Session Cookie', desc: 'Inject a session cookie directly', icon: '🍪' },
]

const SCAN_TYPES = [
  { id: 'sql_injection', label: 'SQL Injection', desc: 'Test for SQL injection vulnerabilities', icon: '💉' },
  { id: 'xss', label: 'Cross-Site Scripting', desc: 'Detect reflected and stored XSS', icon: '📜' },
  { id: 'open_redirect', label: 'Open Redirect', desc: 'Test for URL redirect flaws', icon: '↗️' },
  { id: 'security_headers', label: 'Security Headers', desc: 'Check for missing security headers', icon: '🔒' },
  { id: 'ssti', label: 'Template Injection', desc: 'Server-side template injection', icon: '🧩' },
]

const DEPTH_LABELS = {
  1: 'Shallow — Entry page only',
  2: 'Light — 1-2 levels deep',
  3: 'Standard — 3 levels (recommended)',
  4: 'Deep — 4 levels',
  5: 'Full — Maximum depth',
}

export default function NewScan() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    target_url: '',
    scan_depth: 3,
    scan_types: ['sql_injection', 'xss', 'security_headers'],
    authorized: false,
    target_name: '',
    // Auth fields
    auth_type: null,
    login_url: '',
    username: '',
    password: '',
    username_field: '',
    password_field: '',
    jwt_token: '',
    session_cookie: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const toggleScanType = (type) => {
    setForm(f => ({
      ...f,
      scan_types: f.scan_types.includes(type)
        ? f.scan_types.filter(t => t !== type)
        : [...f.scan_types, type],
    }))
  }

  const handleSubmit = async () => {
    if (!form.target_url) return setError('Target URL is required')
    if (!form.authorized) return setError('You must confirm authorization before scanning')
    if (form.scan_types.length === 0) return setError('Select at least one scan type')

    setLoading(true)
    setError('')

    let url = form.target_url.trim()
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://' + url
    }
    // Strip trailing slash for consistency
    url = url.replace(/\/+$/, '')

    try {
      // Build request body — only include auth fields if auth_type is set
      const body = { ...form, target_url: url }
      if (!body.auth_type || body.auth_type === 'none') {
        delete body.auth_type
        delete body.login_url
        delete body.username
        delete body.password
        delete body.username_field
        delete body.password_field
        delete body.jwt_token
        delete body.session_cookie
      }

      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to start scan')
      navigate(`/live/${data.scan_id}`)
    } catch (e) {
      setError(e.message)
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 bg-aegis-accent/20 rounded-xl flex items-center justify-center border border-aegis-accent/30">
            <Target size={18} className="text-aegis-accent" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-white">New Security Scan</h1>
            <p className="text-sm text-aegis-muted">Configure and launch an autonomous vulnerability assessment</p>
          </div>
        </div>
      </div>

      <div className="space-y-5">
        {/* Target URL */}
        <div className="card p-5">
          <label className="block text-sm font-semibold text-aegis-text mb-3">
            <Target size={14} className="inline mr-2 text-aegis-accent" />
            Target URL
          </label>
          <input
            type="text"
            value={form.target_url}
            onChange={e => setForm(f => ({ ...f, target_url: e.target.value }))}
            placeholder="https://example.com"
            className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-4 py-3 text-aegis-text font-mono text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
          />
          <p className="text-xs text-aegis-muted/60 mt-1.5 px-1">
            💡 Enter a domain or full URL — e.g. <span className="text-aegis-muted font-mono">example.com</span>, <span className="text-aegis-muted font-mono">http://localhost:3000</span>, or <span className="text-aegis-muted font-mono">https://myapp.com</span>
          </p>
          <input
            type="text"
            value={form.target_name}
            onChange={e => setForm(f => ({ ...f, target_name: e.target.value }))}
            placeholder="Optional: friendly name (e.g. My Test App)"
            className="w-full mt-3 bg-aegis-bg border border-aegis-border rounded-lg px-4 py-2.5 text-aegis-text text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
          />
        </div>

        {/* Scan Depth */}
        <div className="card p-5">
          <label className="block text-sm font-semibold text-aegis-text mb-3">
            <Zap size={14} className="inline mr-2 text-aegis-accent" />
            Crawl Depth — <span className="text-aegis-accent">{DEPTH_LABELS[form.scan_depth]}</span>
          </label>
          <input
            type="range"
            min={1} max={5} step={1}
            value={form.scan_depth}
            onChange={e => setForm(f => ({ ...f, scan_depth: parseInt(e.target.value) }))}
            className="w-full accent-indigo-500 cursor-pointer"
          />
          <div className="flex justify-between text-xs text-aegis-muted mt-1 font-mono">
            <span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>
          </div>
        </div>

        {/* Scan Types */}
        <div className="card p-5">
          <label className="block text-sm font-semibold text-aegis-text mb-3">
            <Shield size={14} className="inline mr-2 text-aegis-accent" />
            Vulnerability Tests
          </label>
          <div className="grid grid-cols-1 gap-2">
            {SCAN_TYPES.map(type => {
              const selected = form.scan_types.includes(type.id)
              return (
                <button
                  key={type.id}
                  onClick={() => toggleScanType(type.id)}
                  className={`flex items-center gap-3 p-3 rounded-lg border text-left transition-all ${
                    selected
                      ? 'bg-aegis-accent/10 border-aegis-accent/40 text-aegis-text'
                      : 'bg-aegis-bg border-aegis-border text-aegis-muted hover:border-aegis-muted'
                  }`}
                >
                  <span className="text-xl leading-none">{type.icon}</span>
                  <div className="flex-1">
                    <div className="text-sm font-semibold">{type.label}</div>
                    <div className="text-xs opacity-70">{type.desc}</div>
                  </div>
                  <div className={`w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 transition-all ${
                    selected ? 'bg-aegis-accent border-aegis-accent' : 'border-aegis-border'
                  }`}>
                    {selected && <CheckCircle size={12} className="text-white" />}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* Authenticated Scanning */}
        <div className="card p-5">
          <label className="block text-sm font-semibold text-aegis-text mb-3">
            <LogIn size={14} className="inline mr-2 text-aegis-accent" />
            Authenticated Scanning
          </label>
          <p className="text-xs text-aegis-muted/60 mb-3">
            Enable to scan pages behind login (dashboards, admin panels, user settings)
          </p>
          <div className="grid grid-cols-2 gap-2 mb-4">
            {AUTH_TYPES.map(type => {
              const selected = (form.auth_type || 'none') === type.id
              return (
                <button
                  key={type.id}
                  onClick={() => setForm(f => ({ ...f, auth_type: type.id === 'none' ? null : type.id }))}
                  className={`flex items-center gap-2 p-2.5 rounded-lg border text-left transition-all ${
                    selected
                      ? 'bg-aegis-accent/10 border-aegis-accent/40 text-aegis-text'
                      : 'bg-aegis-bg border-aegis-border text-aegis-muted hover:border-aegis-muted'
                  }`}
                >
                  <span className="text-base leading-none">{type.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold truncate">{type.label}</div>
                    <div className="text-[10px] opacity-60 truncate">{type.desc}</div>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Form Login Fields */}
          {form.auth_type === 'form' && (
            <div className="space-y-3 pt-3 border-t border-aegis-border">
              <div>
                <label className="block text-xs font-medium text-aegis-muted mb-1">Login Page URL</label>
                <input
                  type="text"
                  value={form.login_url}
                  onChange={e => setForm(f => ({ ...f, login_url: e.target.value }))}
                  placeholder="https://example.com/login"
                  className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text font-mono text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-aegis-muted mb-1">Username</label>
                  <input
                    type="text"
                    value={form.username}
                    onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                    placeholder="admin"
                    className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-aegis-muted mb-1">Password</label>
                  <input
                    type="password"
                    value={form.password}
                    onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                    placeholder="••••••••"
                    className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-aegis-muted mb-1">Username Field <span className="opacity-50">(optional)</span></label>
                  <input
                    type="text"
                    value={form.username_field}
                    onChange={e => setForm(f => ({ ...f, username_field: e.target.value }))}
                    placeholder="username"
                    className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-aegis-muted mb-1">Password Field <span className="opacity-50">(optional)</span></label>
                  <input
                    type="text"
                    value={form.password_field}
                    onChange={e => setForm(f => ({ ...f, password_field: e.target.value }))}
                    placeholder="password"
                    className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text text-sm placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                  />
                </div>
              </div>
              <p className="text-[10px] text-aegis-muted/50 px-1">
                Field names are auto-detected. Only fill if the login form uses non-standard input names.
              </p>
            </div>
          )}

          {/* JWT Token Field */}
          {form.auth_type === 'jwt' && (
            <div className="space-y-3 pt-3 border-t border-aegis-border">
              <div>
                <label className="block text-xs font-medium text-aegis-muted mb-1">
                  <Key size={12} className="inline mr-1" />
                  JWT / Bearer Token
                </label>
                <input
                  type="text"
                  value={form.jwt_token}
                  onChange={e => setForm(f => ({ ...f, jwt_token: e.target.value }))}
                  placeholder="eyJhbGciOiJIUzI1NiIs..."
                  className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text font-mono text-xs placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                />
                <p className="text-[10px] text-aegis-muted/50 mt-1 px-1">
                  Sent as <span className="font-mono">Authorization: Bearer &lt;token&gt;</span> on every request
                </p>
              </div>
            </div>
          )}

          {/* Session Cookie Field */}
          {form.auth_type === 'cookie' && (
            <div className="space-y-3 pt-3 border-t border-aegis-border">
              <div>
                <label className="block text-xs font-medium text-aegis-muted mb-1">
                  <Cookie size={12} className="inline mr-1" />
                  Session Cookie
                </label>
                <input
                  type="text"
                  value={form.session_cookie}
                  onChange={e => setForm(f => ({ ...f, session_cookie: e.target.value }))}
                  placeholder="session_id=abc123; csrf_token=xyz789"
                  className="w-full bg-aegis-bg border border-aegis-border rounded-lg px-3 py-2 text-aegis-text font-mono text-xs placeholder-aegis-muted/50 focus:outline-none focus:border-aegis-accent transition-colors"
                />
                <p className="text-[10px] text-aegis-muted/50 mt-1 px-1">
                  Paste cookie string from browser DevTools — <span className="font-mono">name=value; name2=value2</span>
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Authorization */}
        <div className={`card p-5 border-2 transition-colors ${
          form.authorized ? 'border-emerald-700 bg-emerald-950/20' : 'border-aegis-border'
        }`}>
          <button
            onClick={() => setForm(f => ({ ...f, authorized: !f.authorized }))}
            className="flex items-start gap-3 w-full text-left"
          >
            <div className={`w-6 h-6 rounded border-2 flex items-center justify-center flex-shrink-0 mt-0.5 transition-all ${
              form.authorized ? 'bg-emerald-500 border-emerald-500' : 'border-amber-600'
            }`}>
              {form.authorized && <CheckCircle size={14} className="text-white" />}
            </div>
            <div>
              <div className="flex items-center gap-2 font-semibold text-sm">
                <Lock size={14} className={form.authorized ? 'text-emerald-400' : 'text-amber-400'} />
                <span className={form.authorized ? 'text-emerald-400' : 'text-amber-400'}>
                  Authorization Confirmation
                </span>
              </div>
              <p className="text-xs text-aegis-muted mt-1 leading-relaxed">
                I confirm I am the owner of the target system or have explicit written permission
                to perform security testing. I understand that unauthorized scanning is illegal.
              </p>
            </div>
          </button>
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-3 p-4 bg-red-950/40 border border-red-700 rounded-xl">
            <AlertTriangle size={16} className="text-red-400 flex-shrink-0" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Submit */}
        <button
          onClick={handleSubmit}
          disabled={loading || !form.authorized || !form.target_url}
          className={`w-full flex items-center justify-center gap-3 py-4 rounded-xl font-bold text-base transition-all ${
            loading || !form.authorized || !form.target_url
              ? 'bg-aegis-border text-aegis-muted cursor-not-allowed'
              : 'bg-aegis-accent hover:bg-aegis-accent-glow text-white shadow-xl shadow-aegis-accent/30 hover:shadow-aegis-accent/50'
          }`}
        >
          {loading ? (
            <>
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Launching Scan...
            </>
          ) : (
            <>
              <Play size={18} />
              Launch Aegis Scan
            </>
          )}
        </button>

        {/* Info */}
        <div className="flex items-start gap-2 text-xs text-aegis-muted/60 px-1">
          <Info size={12} className="mt-0.5 flex-shrink-0" />
          <span>
            The AI orchestrator will coordinate multiple specialized agents to discover
            endpoints, test for vulnerabilities, and generate a full security report.
          </span>
        </div>
      </div>
    </div>
  )
}
