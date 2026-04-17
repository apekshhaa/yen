import { AlertCircle } from 'lucide-react'
import { ReactNode } from 'react'

interface ContainerProps {
  children: ReactNode
  title?: string
  subtitle?: string
}

export function Container({ children, title, subtitle }: ContainerProps) {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-12">
      {title && (
        <div className="mb-12 animate-fade-in">
          <h1 className="section-title mb-3">
            {title}
          </h1>
          {subtitle && (
            <p className="section-subtitle">
              {subtitle}
            </p>
          )}
          <div className="gradient-separator mt-6"></div>
        </div>
      )}
      {children}
    </div>
  )
}

interface LoadingProps {
  message?: string
  fullPage?: boolean
}

export function Loading({ message = 'Loading...', fullPage = false }: LoadingProps) {
  const content = (
    <div className="flex flex-col items-center justify-center py-16">
      <div className="spinner-lg mb-6"></div>
      <p className="text-slate-600 dark:text-slate-400 font-semibold">{message}</p>
      <p className="text-xs text-slate-500 dark:text-slate-500 mt-2">This may take a moment...</p>
    </div>
  )

  if (fullPage) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        {content}
      </div>
    )
  }

  return content
}

interface ErrorProps {
  message: string
  onRetry?: () => void
}

export function Error({ message, onRetry }: ErrorProps) {
  return (
    <div className="premium-glass rounded-xl p-8 border-l-4 border-red-500 animate-fade-in">
      <div className="flex items-start space-x-4">
        <div className="flex-shrink-0">
          <AlertCircle className="w-6 h-6 text-red-600 dark:text-red-400 mt-0.5" />
        </div>
        <div className="flex-1">
          <h3 className="font-playfair font-bold text-lg text-slate-900 dark:text-red-100 mb-1">
            Something went wrong
          </h3>
          <p className="text-slate-700 dark:text-red-200 mb-4">
            {message}
          </p>
          {onRetry && (
            <button
              onClick={onRetry}
              className="btn-outline text-sm"
            >
              Try Again
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

interface EmptyStateProps {
  title: string
  description: string
  icon?: ReactNode
  action?: { label: string; onClick: () => void }
}

export function EmptyState({ title, description, icon, action }: EmptyStateProps) {
  return (
    <div className="premium-glass rounded-xl p-16 text-center animate-fade-in">
      {icon && (
        <div className="flex justify-center mb-6 text-5xl opacity-40">
          {icon}
        </div>
      )}
      <h3 className="text-2xl font-playfair font-bold text-slate-900 dark:text-white mb-3">
        {title}
      </h3>
      <p className="text-slate-600 dark:text-slate-400 mb-8 max-w-md mx-auto">
        {description}
      </p>
      {action && (
        <button
          onClick={action.onClick}
          className="btn-primary"
        >
          {action.label}
        </button>
      )}
    </div>
  )
}
