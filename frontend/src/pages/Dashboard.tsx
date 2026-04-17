import { Shield, AlertTriangle, CheckCircle, Zap, ArrowRight, Lock, Radar, Brain } from 'lucide-react'
import { useAssessments } from '../hooks/useAssessments'
import { Container, Loading, Error } from '../components/Layout'
import { StatCard, ProgressBar } from '../components/Card'

interface DashboardProps {
  setCurrentPage?: (page: 'dashboard' | 'assessments' | 'findings' | 'compliance' | 'audit') => void
}

export function Dashboard({ setCurrentPage }: DashboardProps) {
  const { assessments, loading, error } = useAssessments()

  if (error) return <Error message={error} />

  const totalAssessments = assessments.length
  const completedAssessments = assessments.filter(a => a.status === 'completed').length
  const runningAssessments = assessments.filter(a => a.status === 'running').length
  const totalFindings = assessments.reduce((sum, a) => sum + a.findingsCount, 0)

  const complianceScore = completedAssessments > 0 
    ? Math.round((completedAssessments / totalAssessments) * 100)
    : 0

  return (
    <>
      {/* Hero Section */}
      {loading ? (
        <Loading message="Loading dashboard..." fullPage={true} />
      ) : (
        <>
          <div className="hero-container">
            <div className="hero-glow"></div>
            <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 md:py-32">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                {/* Left Content */}
                <div className="space-y-8 animate-fade-in">
                  <div className="space-y-4">
                    <div className="inline-block">
                      <span className="px-4 py-2 bg-indigo-500/20 text-indigo-300 rounded-full text-sm font-semibold border border-indigo-400/30">
                        🛡️ Enterprise Security Intelligence
                      </span>
                    </div>
                    <h1 className="text-5xl md:text-6xl lg:text-7xl font-playfair font-bold text-white leading-tight">
                      Autonomous <span className="gradient-text">Penetration Testing</span>
                    </h1>
                    <p className="text-xl text-slate-300 max-w-lg">
                      Major Project harnesses AI-powered security agents to identify vulnerabilities, verify exploits, and deliver comprehensive security reports—all with human oversight and safety guardrails.
                    </p>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-4">
                    <button 
                      onClick={() => setCurrentPage?.('assessments')}
                      className="btn-primary flex items-center justify-center gap-2 group"
                    >
                      <span>Start Security Assessment</span>
                      <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                    </button>
                    <button className="btn-outline flex items-center justify-center gap-2">
                      <span>Learn More</span>
                    </button>
                  </div>

                  {/* Features Grid */}
                  <div className="grid grid-cols-3 gap-4 pt-4">
                    <div className="flex items-center gap-2">
                      <Brain className="w-5 h-5 text-violet-400" />
                      <span className="text-sm text-slate-300">AI-Powered</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Radar className="w-5 h-5 text-cyan-400" />
                      <span className="text-sm text-slate-300">Real-time</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Lock className="w-5 h-5 text-emerald-400" />
                      <span className="text-sm text-slate-300">Secure</span>
                    </div>
                  </div>
                </div>

                {/* Right Visualization */}
                <div className="hidden lg:flex items-center justify-center animate-float">
                  <div className="relative w-80 h-80">
                    {/* Animated background circles */}
                    <div className="absolute inset-0 rounded-full bg-gradient-to-r from-indigo-600/20 to-violet-600/20 blur-3xl animate-pulse-glow"></div>
                    <div className="absolute inset-12 rounded-full bg-gradient-to-r from-cyan-500/20 to-emerald-500/20 blur-2xl animate-pulse-glow" style={{ animationDelay: '0.5s' }}></div>
                    
                    {/* Shield Icon */}
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="relative">
                        <Shield className="w-32 h-32 text-indigo-400 opacity-80" />
                        <div className="absolute inset-0 animate-pulse">
                          <Shield className="w-32 h-32 text-violet-400 opacity-30" />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main Dashboard */}
          <Container title="Security Dashboard" subtitle="Real-time assessment overview and security metrics">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16 animate-fade-in">
              <StatCard
                icon={<Shield className="w-8 h-8" />}
                label="Total Assessments"
                value={totalAssessments}
                color="purple"
              />
              <StatCard
                icon={<Zap className="w-8 h-8" />}
                label="Active Now"
                value={runningAssessments}
                color="blue"
                trend={runningAssessments > 0 ? 5 : 0}
              />
              <StatCard
                icon={<CheckCircle className="w-8 h-8" />}
                label="Completed"
                value={completedAssessments}
                color="green"
              />
              <StatCard
                icon={<AlertTriangle className="w-8 h-8" />}
                label="Findings Detected"
                value={totalFindings}
                color="red"
                trend={totalFindings > 10 ? 12 : 0}
              />
            </div>

            {/* Recent Assessments */}
            <div className="premium-glass rounded-2xl p-10 backdrop-blur-xl mb-16 animate-fade-in">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-2xl md:text-3xl font-playfair font-bold text-slate-900 dark:text-white">
                    Recent Assessments
                  </h2>
                  <p className="text-slate-600 dark:text-slate-400 mt-1">Track your ongoing security evaluations</p>
                </div>
                <button className="btn-primary text-sm">
                  View All
                </button>
              </div>

              {assessments.length === 0 ? (
                <div className="text-center py-16">
                  <Radar className="w-16 h-16 text-slate-300 dark:text-slate-600 mx-auto mb-4 opacity-50" />
                  <p className="text-slate-600 dark:text-slate-400 text-lg font-medium">
                    No assessments yet
                  </p>
                  <p className="text-slate-500 dark:text-slate-500 mt-1">
                    Start by creating a new security assessment or vulnerability scan.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {assessments.slice(0, 5).map((assessment, idx) => (
                    <div
                      key={assessment.id}
                      className="group premium-glass-sm rounded-xl p-5 hover:shadow-xl transition-all duration-300 border border-white/20 dark:border-slate-700/30 animate-fade-in"
                      style={{ animationDelay: `${idx * 50}ms` }}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                            {assessment.name}
                          </h3>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            {new Date(assessment.createdAt).toLocaleDateString()} • ID: {assessment.id.substring(0, 8)}
                          </p>
                        </div>
                        <span className={`px-4 py-2 rounded-lg text-sm font-semibold whitespace-nowrap ml-4 ${
                          assessment.status === 'completed' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' :
                          assessment.status === 'running' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 flex items-center gap-2' :
                          assessment.status === 'failed' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' :
                          'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
                        }`}>
                          {assessment.status === 'running' && <Zap className="w-3 h-3 animate-pulse" />}
                          {assessment.status.charAt(0).toUpperCase() + assessment.status.slice(1)}
                        </span>
                      </div>
                      <ProgressBar value={assessment.progress} showPercentage={false} color="indigo" />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Compliance Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
              {['OWASP Top 10', 'NIST CSF', 'CIS Controls'].map((framework, idx) => (
                <div 
                  key={framework} 
                  className="premium-glass rounded-2xl p-8 backdrop-blur-xl card-effect"
                  style={{ animationDelay: `${idx * 100}ms` }}
                >
                  <h3 className="font-semibold text-slate-900 dark:text-white text-lg mb-6 flex items-center gap-2">
                    <Lock className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                    {framework}
                  </h3>
                  <div className="mb-6">
                    <ProgressBar value={Math.random() * 100} label="Compliance Score" color="indigo" />
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <p className="text-slate-500 dark:text-slate-400">
                      Last assessed: 2 days ago
                    </p>
                    <button className="text-indigo-600 dark:text-indigo-400 font-semibold hover:underline">
                      Details →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Container>
        </>
      )}
    </>
  )
}
