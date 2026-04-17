import { useState, useEffect } from 'react'
import { Filter, AlertTriangle, CheckCircle, Search } from 'lucide-react'
import { assessmentService } from '../services/assessmentService'
import { Container, Loading, Error, EmptyState } from '../components/Layout'
import { FindingBadge } from '../components/Card'

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'

export function Findings() {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const data = await assessmentService.getFindings()
        setFindings(data)
      } catch (err) {
        setError('Failed to fetch findings')
      } finally {
        setLoading(false)
      }
    }
    fetchFindings()
  }, [])

  if (error) return <Error message={error} />
  if (loading) return <Loading />

  const filteredFindings = findings
    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
    .filter(f => searchTerm === '' || f.title.toLowerCase().includes(searchTerm.toLowerCase()))

  const severityCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  }

  return (
    <Container
      title="Security Findings"
      subtitle="Identified vulnerabilities and security issues from assessments"
    >
      {/* Filter & Search Bar */}
      <div className="premium-glass rounded-2xl p-8 backdrop-blur-xl mb-8 animate-fade-in">
        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              type="text"
              placeholder="Search findings by title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-field pl-12"
            />
          </div>
        </div>

        {/* Severity Filter */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
            <h3 className="font-semibold text-slate-900 dark:text-white">Filter by Severity</h3>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => setSeverityFilter('all')}
              className={`px-4 py-2 rounded-lg font-semibold transition-all ${
                severityFilter === 'all'
                  ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-lg shadow-indigo-600/40'
                  : 'bg-slate-200 dark:bg-slate-700/50 text-slate-900 dark:text-white hover:bg-slate-300 dark:hover:bg-slate-600'
              }`}
            >
              All ({findings.length})
            </button>
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => (
              <button
                key={severity}
                onClick={() => setSeverityFilter(severity)}
                className={`px-4 py-2 rounded-lg font-semibold transition-all ${
                  severityFilter === severity
                    ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-lg shadow-indigo-600/40'
                    : 'bg-slate-200 dark:bg-slate-700/50 text-slate-900 dark:text-white hover:bg-slate-300 dark:hover:bg-slate-600'
                }`}
              >
                {severity.charAt(0).toUpperCase() + severity.slice(1)} ({severityCounts[severity]})
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Findings Grid */}
      {filteredFindings.length === 0 ? (
        <EmptyState
          title="No Findings"
          description={severityFilter === 'all' && searchTerm === ''
            ? 'Excellent! No security issues were discovered in the latest assessments.'
            : `No results found for your current filters.`
          }
          icon={<CheckCircle className="w-12 h-12 text-emerald-500" />}
        />
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding, idx) => (
            <div
              key={finding.id}
              className="premium-glass rounded-2xl p-8 backdrop-blur-xl card-effect border border-white/30 dark:border-slate-700/50 hover:border-indigo-500/50 dark:hover:border-violet-500/50 group animate-fade-in"
              style={{ animationDelay: `${idx * 50}ms` }}
            >
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-playfair font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-violet-400 transition-colors">
                      {finding.title}
                    </h3>
                    <FindingBadge severity={finding.severity} />
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">
                    ID: {finding.id.substring(0, 12)}...
                  </p>
                </div>
              </div>

              <p className="text-slate-700 dark:text-slate-300 mb-6 leading-relaxed">
                {finding.description}
              </p>

              {/* Recommendation Box */}
              <div className="mb-6 p-6 bg-gradient-to-br from-indigo-50 dark:from-indigo-950/30 to-violet-50 dark:to-violet-950/30 rounded-xl border border-indigo-200 dark:border-indigo-800/50">
                <p className="text-sm font-bold text-indigo-900 dark:text-indigo-200 mb-2 uppercase tracking-wide">
                  🔧 Remediation Steps
                </p>
                <p className="text-slate-700 dark:text-slate-300 text-sm leading-relaxed">
                  {finding.recommendation}
                </p>
              </div>

              {/* Affected Assets */}
              {finding.affectedAssets && finding.affectedAssets.length > 0 && (
                <div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-white mb-3 uppercase tracking-wide">
                    📍 Affected Assets
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {finding.affectedAssets.map((asset: string) => (
                      <span
                        key={asset}
                        className="px-4 py-2 bg-slate-100 dark:bg-slate-700/50 text-slate-900 dark:text-white text-xs font-semibold rounded-full border border-slate-200 dark:border-slate-600"
                      >
                        {asset}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Container>
  )
}
