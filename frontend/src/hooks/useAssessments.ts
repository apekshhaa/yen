import { useState, useEffect } from 'react'
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api'

interface Assessment {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  createdAt: string
  updatedAt: string
  progress: number
  findingsCount: number
}

export const useAssessments = () => {
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchAssessments = async () => {
    setLoading(true)
    try {
      const response = await axios.get(`${API_BASE}/assessments`)
      setAssessments(response.data || [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch assessments')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAssessments()
    const interval = setInterval(fetchAssessments, 5000)
    return () => clearInterval(interval)
  }, [])

  return { assessments, loading, error, refetch: fetchAssessments }
}
