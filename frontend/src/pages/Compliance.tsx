import { useState, useEffect } from 'react'
import { CheckCircle, AlertCircle } from 'lucide-react'
import { assessmentService } from '../services/assessmentService'
import { Container, Loading, Error, EmptyState } from '../components/Layout'
import { ProgressBar } from '../components/Card'

export function Compliance() {
  const [reports, setReports] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const data = await assessmentService.getComplianceReports()
        setReports(data)
      } catch (err) {
        setError('Failed to fetch compliance reports')
      } finally {
        setLoading(false)
      }
    }
    fetchReports()
  }, [])

  if (error) return <Error message={error} />
  if (loading) return <Loading />

  const overallCompliance = reports.length > 0
    ? Math.round(reports.reduce((sum, r) => sum + r.compliance, 0) / reports.length)
    : 0

  return (
    <Container
      title="Compliance"
      subtitle="Compliance framework assessment and reporting"
    >
      {/* Overall Compliance Score */}
      <div className="glass-effect rounded-xl p-8 backdrop-blur-xl mb-12 bg-gradient-to-br from-green-500/10 to-emerald-500/10">
        <div className="text-center">
          <p className="text-sm font-medium text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-2">
            Overall Compliance Score
          </p>
          <div className="text-6xl font-bold gradient-text mb-4">
            {overallCompliance}%
          </div>
          <p className="text-slate-600 dark:text-slate-400">
            Across {reports.length} compliance framework{reports.length !== 1 ? 's' : ''}
          </p>
        </div>
      </div>

      {/* Compliance Reports Grid */}
      {reports.length === 0 ? (
        <EmptyState
          title="No Compliance Reports"
          description="Run assessments to generate compliance reports against industry frameworks."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {reports.map((report) => (
            <div
              key={report.framework}
              className="glass-effect rounded-xl p-8 backdrop-blur-xl"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
                  {report.framework}
                </h3>
                {report.status === 'compliant' ? (
                  <CheckCircle className="w-8 h-8 text-green-500" />
                ) : (
                  <AlertCircle className="w-8 h-8 text-red-500" />
                )}
              </div>

              <div className="mb-6">
                <ProgressBar
                  value={report.compliance}
                  label="Compliance Score"
                  showPercentage
                />
              </div>

              <div className="mb-6">
                <span className={`inline-block px-4 py-2 rounded-lg font-medium ${
                  report.status === 'compliant'
                    ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                    : report.status === 'partial'
                    ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
                    : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                }`}>
                  {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                </span>
              </div>

              {report.failedControls && report.failedControls.length > 0 && (
                <div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-white mb-3">
                    Failed Controls ({report.failedControls.length})
                  </p>
                  <div className="space-y-2">
                    {report.failedControls.slice(0, 5).map((control: any, index: number) => (
                      <div
                        key={index}
                        className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800"
                      >
                        <p className="text-sm font-medium text-red-900 dark:text-red-300">
                          {control.control}
                        </p>
                        <p className="text-xs text-red-700 dark:text-red-400 mt-1">
                          {control.finding}
                        </p>
                      </div>
                    ))}
                    {report.failedControls.length > 5 && (
                      <p className="text-xs text-slate-600 dark:text-slate-400 mt-2">
                        +{report.failedControls.length - 5} more controls
                      </p>
                    )}
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
