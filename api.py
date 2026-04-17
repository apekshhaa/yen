"""
Simple FastAPI wrapper for ODSAF frontend
Provides REST endpoints that the React frontend expects
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import uuid

app = FastAPI(
    title="ODSAF API",
    description="Open Data Security Assessment Framework - REST API",
    version="1.0.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock data for demo
mock_assessments = [
    {
        "id": str(uuid.uuid4()),
        "name": "Q1 2026 Security Audit",
        "status": "completed",
        "createdAt": (datetime.now() - timedelta(days=5)).isoformat(),
        "updatedAt": (datetime.now() - timedelta(days=1)).isoformat(),
        "progress": 100,
        "findingsCount": 12
    },
    {
        "id": str(uuid.uuid4()),
        "name": "API Security Review",
        "status": "running",
        "createdAt": datetime.now().isoformat(),
        "updatedAt": datetime.now().isoformat(),
        "progress": 65,
        "findingsCount": 5
    }
]

mock_findings = [
    {
        "id": str(uuid.uuid4()),
        "assessmentId": mock_assessments[0]["id"],
        "title": "SQL Injection Vulnerability",
        "severity": "critical",
        "description": "User input is not properly sanitized before being used in SQL queries",
        "recommendation": "Use parameterized queries and prepared statements",
        "affectedAssets": ["api.example.com", "db.example.com"],
        "createdAt": datetime.now().isoformat()
    },
    {
        "id": str(uuid.uuid4()),
        "assessmentId": mock_assessments[0]["id"],
        "title": "Missing HTTPS",
        "severity": "high",
        "description": "Some endpoints do not enforce HTTPS encryption",
        "recommendation": "Implement HTTPS on all endpoints and redirect HTTP traffic",
        "affectedAssets": ["dashboard.example.com"],
        "createdAt": datetime.now().isoformat()
    },
    {
        "id": str(uuid.uuid4()),
        "assessmentId": mock_assessments[0]["id"],
        "title": "Weak Password Policy",
        "severity": "medium",
        "description": "Password requirements are not enforced",
        "recommendation": "Implement strong password policies (minimum 12 chars, complexity)",
        "affectedAssets": ["auth.example.com"],
        "createdAt": datetime.now().isoformat()
    },
]

mock_compliance = [
    {
        "framework": "OWASP Top 10",
        "compliance": 72,
        "status": "partial",
        "failedControls": [
            {"control": "A1:2021 - Injection", "finding": "SQL Injection found in user input"},
            {"control": "A5:2021 - ACSII", "finding": "Broken access control on admin panel"},
        ]
    },
    {
        "framework": "NIST CSF",
        "compliance": 85,
        "status": "partial",
        "failedControls": [
            {"control": "PR.AC-1", "finding": "MFA not enforced for admin accounts"},
        ]
    },
    {
        "framework": "CIS Controls",
        "compliance": 68,
        "status": "non-compliant",
        "failedControls": [
            {"control": "v8.1", "finding": "Inventory of hardware not maintained"},
            {"control": "v8.2", "finding": "Software inventory incomplete"},
        ]
    }
]

mock_audit = [
    {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "action": "Assessment Started",
        "userId": "admin-001",
        "details": {"assessmentId": mock_assessments[0]["id"], "scope": "full"},
        "status": "success"
    },
    {
        "id": str(uuid.uuid4()),
        "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
        "action": "Finding Created",
        "userId": "system",
        "details": {"findingId": mock_findings[0]["id"], "severity": "critical"},
        "status": "success"
    },
    {
        "id": str(uuid.uuid4()),
        "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
        "action": "Compliance Report Generated",
        "userId": "admin-001",
        "details": {"framework": "OWASP Top 10"},
        "status": "success"
    },
]


@app.get("/")
async def root():
    """API Health check"""
    return {
        "status": "ok",
        "message": "ODSAF API is running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat() + "Z",
        "services": ["analysis", "prediction", "reporting"]
    }


# Assessment Endpoints
@app.get("/api/assessments")
async def get_assessments():
    """List all assessments"""
    return mock_assessments


@app.get("/api/assessments/{assessment_id}")
async def get_assessment(assessment_id: str):
    """Get single assessment"""
    for assessment in mock_assessments:
        if assessment["id"] == assessment_id:
            return assessment
    return JSONResponse({"error": "Assessment not found"}, status_code=404)


@app.post("/api/assessments")
async def create_assessment(payload: dict):
    """Create new assessment"""
    assessment = {
        "id": str(uuid.uuid4()),
        "name": payload.get("name", "Untitled Assessment"),
        "status": "pending",
        "createdAt": datetime.now().isoformat(),
        "updatedAt": datetime.now().isoformat(),
        "progress": 0,
        "findingsCount": 0
    }
    mock_assessments.append(assessment)
    return assessment


# Findings Endpoints
@app.get("/api/findings")
async def get_findings():
    """List all findings"""
    return mock_findings


@app.get("/api/assessments/{assessment_id}/findings")
async def get_assessment_findings(assessment_id: str):
    """Get findings for a specific assessment"""
    return [f for f in mock_findings if f["assessmentId"] == assessment_id]


# Compliance Endpoints
@app.get("/api/compliance-reports")
async def get_compliance_reports():
    """Get compliance reports"""
    return mock_compliance


# Audit Trail Endpoints
@app.get("/api/audit-trail")
async def get_audit_trail():
    """Get audit trail"""
    return mock_audit


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
