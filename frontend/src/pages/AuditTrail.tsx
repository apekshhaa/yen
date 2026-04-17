import { useState, useEffect } from 'react'
import { CheckCircle, AlertCircle } from 'lucide-react'
import { assessmentService } from '../services/assessmentService'
import { Container, Loading, Error, EmptyState } from '../components/Layout'

export function AuditTrail() {
  const [records, setRecords] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchAuditTrail = async () => {
      try {
        const data = await assessmentService.getAuditTrail()
        setRecords(data)
      } catch (err) {
        setError('Failed to fetch audit trail')
      } finally {
        setLoading(false)
      }
    }
    fetchAuditTrail()
  }, [])

  if (error) return <Error message={error} />
  if (loading) return <Loading />

  const successCount = records.filter(r => r.status === 'success').length
  const failedCount = records.filter(r => r.status === 'failed').length

  return (
    <Container
      title="Audit Trail"
      subtitle="Complete activity log and system events"
    >
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="glass-effect rounded-xl p-6 backdrop-blur-xl flex items-center space-x-4">
          <CheckCircle className="w-8 h-8 text-green-500" />
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400">Successful Actions</p>
            <p className="text-2xl font-bold text-slate-900 dark:text-white">
              {successCount}
            </p>
          </div>
        </div>
        <div className="glass-effect rounded-xl p-6 backdrop-blur-xl flex items-center space-x-4">
          <AlertCircle className="w-8 h-8 text-red-500" />
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400">Failed Actions</p>
            <p className="text-2xl font-bold text-slate-900 dark:text-white">
              {failedCount}
            </p>
          </div>
        </div>
      </div>

      {/* Audit Records */}
      {records.length === 0 ? (
        <EmptyState
          title="No Audit Records"
          description="Audit events will appear here as you interact with the system."
        />
      ) : (
        <div className="space-y-3">
          {records.map((record) => (
            <div
              key={record.id}
              className="glass-effect rounded-xl p-6 backdrop-blur-xl hover:shadow-lg transition-all duration-300 flex items-start space-x-4"
            >
              <div>
                {record.status === 'success' ? (
                  <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-1" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-1" />
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-semibold text-slate-900 dark:text-white">
                    {record.action}
                  </h3>
                  <span className="text-xs text-slate-500 dark:text-slate-400 flex-shrink-0 ml-4">
                    {new Date(record.timestamp).toLocaleString()}
                  </span>
                </div>

                <div className="flex items-center space-x-2 text-sm text-slate-600 dark:text-slate-400 mb-2">
                  <span className="px-2 py-1 rounded bg-slate-200 dark:bg-slate-700 text-xs font-medium">
                    {record.userId}
                  </span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    record.status === 'success'
                      ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                      : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                  }`}>
                    {record.status.toUpperCase()}
                  </span>
                </div>

                {record.details && Object.keys(record.details).length > 0 && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300">
                      View details
                    </summary>
                    <pre className="mt-2 p-2 bg-slate-100 dark:bg-slate-800 rounded text-slate-600 dark:text-slate-300 overflow-auto max-h-32 text-xs">
                      {JSON.stringify(record.details, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Container>
  )
}
