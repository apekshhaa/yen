import { Plus, CheckCircle, X } from 'lucide-react'
import { useState } from 'react'
import { useAssessments } from '../hooks/useAssessments'
import { assessmentService, CreateAssessmentPayload } from '../services/assessmentService'
import { Container, Loading, Error, EmptyState } from '../components/Layout'
import { StatusBadge, ProgressBar } from '../components/Card'

interface SelectedAssessment {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  createdAt: string
  updatedAt: string
  progress: number
  findingsCount: number
}

export function Assessments() {
  const { assessments, loading, error, refetch } = useAssessments()
  const [showForm, setShowForm] = useState(false)
  const [selectedAssessment, setSelectedAssessment] = useState<SelectedAssessment | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [formData, setFormData] = useState<CreateAssessmentPayload>({
    name: '',
    targetAssets: [],
    scope: 'full',
    complianceFrameworks: [],
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    try {
      await assessmentService.createAssessment(formData)
      setFormData({ name: '', targetAssets: [], scope: 'full', complianceFrameworks: [] })
      setShowForm(false)
      refetch()
    } catch (err) {
      console.error('Failed to create assessment:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  if (error) return <Error message={error} />
  if (loading) return <Loading />

  return (
    <Container title="Security Assessments" subtitle="Create and manage comprehensive security evaluations">
      {/* Create Button */}
      <div className="mb-8 animate-fade-in">
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary flex items-center gap-2 text-lg"
        >
          <Plus className="w-5 h-5" />
          <span>New Assessment</span>
        </button>
      </div>

      {/* Create Form */}
      {showForm && (
        <div className="premium-glass rounded-2xl p-10 backdrop-blur-xl mb-12 animate-fade-in border border-white/30 dark:border-slate-700/50">
          <h2 className="text-3xl font-playfair font-bold text-slate-900 dark:text-white mb-8">
            Create New Assessment
          </h2>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wide">
                Assessment Name
              </label>
              <input
                type="text"
                required
                className="input-field"
                placeholder="e.g., Q4 2024 Security Audit"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wide">
                Target Assets (comma-separated)
              </label>
              <input
                type="text"
                className="input-field"
                placeholder="e.g., api.example.com, dashboard.example.com"
                onChange={(e) => setFormData({
                  ...formData,
                  targetAssets: e.target.value.split(',').map(s => s.trim())
                })}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wide">
                  Scope
                </label>
                <select
                  className="input-field"
                  value={formData.scope}
                  onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
                >
                  <option value="full">Full Scope</option>
                  <option value="external">External Only</option>
                  <option value="internal">Internal Only</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wide">
                  Compliance Frameworks
                </label>
                <select
                  multiple
                  className="input-field"
                  onChange={(e) => setFormData({
                    ...formData,
                    complianceFrameworks: Array.from(e.target.selectedOptions, option => option.value)
                  })}
                >
                  <option value="owasp">OWASP Top 10</option>
                  <option value="nist">NIST CSF</option>
                  <option value="cis">CIS Controls</option>
                </select>
              </div>
            </div>

            <div className="flex gap-4 pt-4">
              <button
                type="submit"
                disabled={isSubmitting}
                className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <div className="flex items-center gap-2">
                    <div className="spinner w-4 h-4"></div>
                    Creating...
                  </div>
                ) : (
                  'Create Assessment'
                )}
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Assessments List */}
      {assessments.length === 0 ? (
        <EmptyState
          title="No Assessments Yet"
          description="Start by creating a new security assessment to begin your security evaluation."
          icon={<CheckCircle className="w-12 h-12 text-emerald-500" />}
          action={{ label: 'Create First Assessment', onClick: () => setShowForm(true) }}
        />
      ) : (
        <div className="space-y-4">
          {assessments.map((assessment, idx) => (
            <div
              key={assessment.id}
              onClick={() => setSelectedAssessment(assessment)}
              className="premium-glass rounded-2xl p-8 backdrop-blur-xl card-effect border border-white/30 dark:border-slate-700/50 hover:border-indigo-500/50 dark:hover:border-violet-500/50 animate-fade-in cursor-pointer transition-all hover:shadow-xl hover:scale-[1.02]"
              style={{ animationDelay: `${idx * 50}ms` }}
            >
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <h3 className="text-2xl font-playfair font-bold text-slate-900 dark:text-white mb-2">
                    {assessment.name}
                  </h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">
                    ID: {assessment.id.substring(0, 12)}... • Created: {new Date(assessment.createdAt).toLocaleDateString()}
                  </p>
                </div>
                <StatusBadge status={assessment.status} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6 pb-6 border-b border-white/20 dark:border-slate-700/30">
                <div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold tracking-wide mb-2">
                    📊 Findings
                  </p>
                  <p className="text-2xl font-playfair font-bold text-slate-900 dark:text-white">
                    {assessment.findingsCount}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">issues found</p>
                </div>
                <div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold tracking-wide mb-2">
                    ⏱ Status
                  </p>
                  <p className="text-2xl font-playfair font-bold text-slate-900 dark:text-white capitalize">
                    {assessment.status}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold tracking-wide mb-2">
                    ✅ Completion
                  </p>
                  <p className="text-2xl font-playfair font-bold gradient-text">
                    {assessment.progress}%
                  </p>
                </div>
              </div>

              <ProgressBar value={assessment.progress} label="Assessment Progress" color="indigo" />
              
              <p className="text-xs text-indigo-500 dark:text-violet-400 mt-4 font-semibold cursor-pointer hover:underline">
                Click to view details →
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Details Modal */}
      {selectedAssessment && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="premium-glass rounded-3xl p-8 backdrop-blur-xl border border-white/30 dark:border-slate-700/50 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-start justify-between mb-8">
              <div>
                <h2 className="text-4xl font-playfair font-bold text-slate-900 dark:text-white mb-2">
                  {selectedAssessment.name}
                </h2>
                <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">
                  Assessment ID: {selectedAssessment.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedAssessment(null)}
                className="p-2 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                <X className="w-6 h-6 text-slate-600 dark:text-slate-400" />
              </button>
            </div>

            {/* Status Badge */}
            <div className="mb-8">
              <StatusBadge status={selectedAssessment.status} />
            </div>

            {/* Details Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8 p-6 bg-slate-50 dark:bg-slate-900/30 rounded-2xl">
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold mb-2">Findings</p>
                <p className="text-3xl font-playfair font-bold text-indigo-600 dark:text-violet-400">
                  {selectedAssessment.findingsCount}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold mb-2">Progress</p>
                <p className="text-3xl font-playfair font-bold gradient-text">
                  {selectedAssessment.progress}%
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold mb-2">Created</p>
                <p className="text-sm text-slate-900 dark:text-slate-200 font-semibold">
                  {new Date(selectedAssessment.createdAt).toLocaleDateString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase font-bold mb-2">Updated</p>
                <p className="text-sm text-slate-900 dark:text-slate-200 font-semibold">
                  {new Date(selectedAssessment.updatedAt).toLocaleDateString()}
                </p>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="mb-8">
              <ProgressBar value={selectedAssessment.progress} label="Assessment Progress" color="indigo" />
            </div>

            {/* Actions */}
            <div className="flex gap-4">
              <button className="flex-1 btn-primary rounded-xl">
                View Findings
              </button>
              <button
                onClick={() => setSelectedAssessment(null)}
                className="flex-1 btn-outline rounded-xl"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </Container>
  )
}
