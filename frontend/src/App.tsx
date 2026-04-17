import { useState, useEffect } from 'react'
import { useTheme } from './hooks/useTheme'
import { Navigation } from './components/Navigation'
import { Dashboard } from './pages/Dashboard'
import { Assessments } from './pages/Assessments'
import { Findings } from './pages/Findings'
import { Compliance } from './pages/Compliance'
import { AuditTrail } from './pages/AuditTrail'

type Page = 'dashboard' | 'assessments' | 'findings' | 'compliance' | 'audit'

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')
  const { isDark, toggleTheme } = useTheme()

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [isDark])

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard setCurrentPage={setCurrentPage} />
      case 'assessments':
        return <Assessments />
      case 'findings':
        return <Findings />
      case 'compliance':
        return <Compliance />
      case 'audit':
        return <AuditTrail />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-50 dark:from-slate-950 dark:via-slate-900 dark:to-black transition-colors duration-300">
      <Navigation 
        currentPage={currentPage} 
        setCurrentPage={setCurrentPage}
        isDark={isDark}
        toggleTheme={toggleTheme}
      />
      <main className="pt-20">
        {renderPage()}
      </main>
    </div>
  )
}
