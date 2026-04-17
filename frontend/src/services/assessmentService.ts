import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api'

export interface CreateAssessmentPayload {
  name: string
  targetAssets: string[]
  scope: string
  complianceFrameworks: string[]
}

export interface Assessment {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  createdAt: string
  updatedAt: string
  progress: number
  findingsCount: number
}

export interface Finding {
  id: string
  assessmentId: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  recommendation: string
  affectedAssets: string[]
  createdAt: string
}

export interface ComplianceReport {
  framework: string
  compliance: number
  status: 'compliant' | 'non-compliant' | 'partial'
  failedControls: { control: string; finding: string }[]
}

export interface AuditRecord {
  id: string
  timestamp: string
  action: string
  userId: string
  details: Record<string, unknown>
  status: 'success' | 'failed'
}

class AssessmentService {
  async createAssessment(payload: CreateAssessmentPayload): Promise<Assessment> {
    const response = await axios.post(`${API_BASE}/assessments`, payload)
    return response.data
  }

  async getAssessments(): Promise<Assessment[]> {
    try {
      const response = await axios.get(`${API_BASE}/assessments`)
      return response.data || []
    } catch {
      return []
    }
  }

  async getAssessment(id: string): Promise<Assessment> {
    const response = await axios.get(`${API_BASE}/assessments/${id}`)
    return response.data
  }

  async getFindings(assessmentId?: string): Promise<Finding[]> {
    try {
      const url = assessmentId 
        ? `${API_BASE}/assessments/${assessmentId}/findings`
        : `${API_BASE}/findings`
      const response = await axios.get(url)
      return response.data || []
    } catch {
      return []
    }
  }

  async getComplianceReports(): Promise<ComplianceReport[]> {
    try {
      const response = await axios.get(`${API_BASE}/compliance-reports`)
      return response.data || []
    } catch {
      return []
    }
  }

  async getAuditTrail(): Promise<AuditRecord[]> {
    try {
      const response = await axios.get(`${API_BASE}/audit-trail`)
      return response.data || []
    } catch {
      return []
    }
  }
}

export const assessmentService = new AssessmentService()
