import { Shield, Zap, AlertTriangle, CheckCircle, Clock, TrendingUp, TrendingDown } from 'lucide-react'
import { clsx } from 'clsx'

interface StatCardProps {
  icon: React.ReactNode
  label: string
  value: string | number
  trend?: number
  color: 'purple' | 'blue' | 'red' | 'green' | 'orange'
}

const colorMap = {
  purple: 'from-indigo-500/20 to-violet-500/20 text-indigo-600 dark:text-indigo-400',
  blue: 'from-cyan-500/20 to-blue-500/20 text-blue-600 dark:text-blue-400',
  red: 'from-red-500/20 to-orange-500/20 text-red-600 dark:text-red-400',
  green: 'from-emerald-500/20 to-teal-500/20 text-emerald-600 dark:text-emerald-400',
  orange: 'from-orange-500/20 to-red-500/20 text-orange-600 dark:text-orange-400',
}

export function StatCard({ icon, label, value, trend, color }: StatCardProps) {
  return (
    <div className={clsx(
      'premium-glass-sm rounded-2xl p-8 backdrop-blur-xl border border-white/30 dark:border-slate-700/50',
      'bg-gradient-to-br',
      colorMap[color],
      'card-effect group'
    )}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-semibold text-slate-600 dark:text-slate-400 mb-2 uppercase tracking-wide">
            {label}
          </p>
          <p className="text-4xl lg:text-5xl font-playfair font-bold text-slate-900 dark:text-white mb-4">
            {value}
          </p>
          {trend !== undefined && (
            <div className={clsx(
              'flex items-center gap-1 text-sm font-semibold',
              trend > 0 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'
            )}>
              {trend > 0 ? (
                <TrendingUp className="w-4 h-4" />
              ) : (
                <TrendingDown className="w-4 h-4" />
              )}
              <span>{Math.abs(trend)}% from last week</span>
            </div>
          )}
        </div>
        <div className="text-4xl opacity-30 group-hover:opacity-50 transition-opacity">
          {icon}
        </div>
      </div>
    </div>
  )
}

interface FindingBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
}

export function FindingBadge({ severity }: FindingBadgeProps) {
  const badgeClass = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  }

  const icons = {
    critical: <AlertTriangle className="w-3.5 h-3.5" />,
    high: <AlertTriangle className="w-3.5 h-3.5" />,
    medium: <AlertTriangle className="w-3.5 h-3.5" />,
    low: <CheckCircle className="w-3.5 h-3.5" />,
    info: <Shield className="w-3.5 h-3.5" />,
  }

  return (
    <div className={badgeClass[severity]}>
      {icons[severity]}
      <span className="capitalize font-semibold">{severity}</span>
    </div>
  )
}

interface ProgressBarProps {
  value: number
  label?: string
  showPercentage?: boolean
  color?: 'indigo' | 'emerald' | 'cyan'
}

export function ProgressBar({ value, label, showPercentage = true, color = 'indigo' }: ProgressBarProps) {
  const colorClass = {
    indigo: 'from-indigo-600 to-violet-600',
    emerald: 'from-emerald-600 to-teal-600',
    cyan: 'from-cyan-500 to-blue-600',
  }

  return (
    <div className="w-full">
      {label && (
        <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">
          {label}
        </p>
      )}
      <div className="w-full h-3 bg-slate-200 dark:bg-slate-700/50 rounded-full overflow-hidden shadow-inner">
        <div
          className={clsx(
            'h-full bg-gradient-to-r rounded-full transition-all duration-700 ease-out shadow-lg',
            colorClass[color],
            value > 0 && 'shadow-lg shadow-indigo-600/30 dark:shadow-violet-600/20'
          )}
          style={{ width: `${Math.min(value, 100)}%` }}
        />
      </div>
      {showPercentage && (
        <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 mt-2">
          {Math.round(value)}% Complete
        </p>
      )}
    </div>
  )
}

interface StatusBadgeProps {
  status: 'pending' | 'running' | 'completed' | 'failed'
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const config = {
    pending: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-700 dark:text-yellow-300', icon: Clock },
    running: { bg: 'bg-blue-100 dark:bg-blue-900/30', text: 'text-blue-700 dark:text-blue-300', icon: Zap },
    completed: { bg: 'bg-emerald-100 dark:bg-emerald-900/30', text: 'text-emerald-700 dark:text-emerald-300', icon: CheckCircle },
    failed: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-700 dark:text-red-300', icon: AlertTriangle },
  }

  const { bg, text, icon: Icon } = config[status]

  return (
    <div className={clsx('badge', bg, text)}>
      <Icon className="w-3.5 h-3.5" />
      <span className="capitalize font-semibold">{status}</span>
    </div>
  )
}
