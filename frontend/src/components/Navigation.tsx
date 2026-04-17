import { Menu, X, Moon, Sun } from 'lucide-react'
import { useState } from 'react'
import { clsx } from 'clsx'

type Page = 'dashboard' | 'assessments' | 'findings' | 'compliance' | 'audit'

interface NavigationProps {
  currentPage: Page
  setCurrentPage: (page: Page) => void
  isDark: boolean
  toggleTheme: () => void
}

const navItems: { label: string; id: Page }[] = [
  { label: 'Dashboard', id: 'dashboard' },
  { label: 'Assessments', id: 'assessments' },
  { label: 'Findings', id: 'findings' },
  { label: 'Compliance', id: 'compliance' },
  { label: 'Audit Trail', id: 'audit' },
]

export function Navigation({
  currentPage,
  setCurrentPage,
  isDark,
  toggleTheme,
}: NavigationProps) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 premium-glass border-b border-white/30 dark:border-slate-700/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          {/* Logo & Brand */}
          <div className="flex-shrink-0">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-600 to-violet-600 rounded-xl flex items-center justify-center shadow-lg">
                <span className="text-white font-playfair font-bold text-lg">M</span>
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-playfair font-bold gradient-text">Major</span>
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-400">Security</span>
              </div>
            </div>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={clsx(
                  'px-4 py-2 rounded-lg font-semibold transition-all duration-300',
                  currentPage === item.id
                    ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-lg shadow-indigo-600/40'
                    : 'text-slate-700 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-violet-400 hover:bg-indigo-50/50 dark:hover:bg-indigo-950/20'
                )}
              >
                {item.label}
              </button>
            ))}
          </div>

          {/* Right Actions */}
          <div className="flex items-center space-x-4">
            <button
              onClick={toggleTheme}
              className="p-2.5 rounded-lg hover:bg-indigo-100 dark:hover:bg-violet-900/30 transition-all duration-300"
              aria-label="Toggle theme"
            >
              {isDark ? (
                <Sun className="w-5 h-5 text-amber-400" />
              ) : (
                <Moon className="w-5 h-5 text-indigo-600" />
              )}
            </button>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="md:hidden p-2.5 rounded-lg hover:bg-indigo-100 dark:hover:bg-violet-900/30 transition-all duration-300"
            >
              {isOpen ? (
                <X className="w-5 h-5 text-slate-900 dark:text-white" />
              ) : (
                <Menu className="w-5 h-5 text-slate-900 dark:text-white" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isOpen && (
          <div className="md:hidden border-t border-white/20 dark:border-slate-700/30 py-4 space-y-2 animate-fade-in">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  setCurrentPage(item.id)
                  setIsOpen(false)
                }}
                className={clsx(
                  'w-full text-left px-4 py-3 rounded-lg font-semibold transition-all duration-300',
                  currentPage === item.id
                    ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-indigo-50/50 dark:hover:bg-indigo-950/20'
                )}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </nav>
  )
}
