# 🛡️ Major Project - AI-Powered Autonomous Penetration Testing Platform

> **Enterprise-Grade Security Intelligence Meets AI Reasoning**

An autonomous, AI-powered penetration testing platform that discovers, analyzes, and validates security vulnerabilities at enterprise scale—with full human oversight, safety guardrails, and professional-grade reporting.

## 🎯 What is Major Project?

Major Project harnesses the power of multi-agent AI coordination to automate the entire penetration testing workflow:

- **🔍 Intelligent Discovery**: AI-powered asset discovery, API enumeration, and attack surface mapping
- **🧠 AI Reasoning**: LLM-driven vulnerability analysis with context-aware prioritization
- **⚡ Safe Exploitation**: Generates and validates proof-of-concept exploits with approval workflows
- **📊 Professional Reporting**: Executive summaries, technical findings, and remediation guidance
- **🔄 Continuous Monitoring**: Tracks attack surface changes and detects new vulnerabilities in real-time
- **🎛️ Human Oversight**: Critical actions require explicit approval; human-in-the-loop at every stage

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Major Project - AI Pentester                     │
│              Autonomous Security Intelligence Platform              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Frontend Dashboard                         │  │
│  │           React 18 + TypeScript + Tailwind CSS              │  │
│  │     • Hero Section • Real-time Metrics • Dark Mode          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    REST API Gateway                           │  │
│  │              FastAPI • Live Health Checks                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │               Temporal Workflow Orchestration                │  │
│  │    WAITING → DISCOVERING → REASONING → EXPLOITING → DONE    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│         │                                                           │
│    ┌────┴────┬────────────┬──────────────┬──────────────┐          │
│    ▼         ▼            ▼              ▼              ▼          │
│  ┌─────┐ ┌──────┐  ┌──────────┐  ┌──────────────┐ ┌────────┐    │
│  │AI   │ │Asset │  │Vuln      │  │Exploit Gen   │ │Report  │    │
│  │Reas │ │Disco │  │Analyzer  │  │& Validation  │ │Engine  │    │
│  │oner │ │very  │  │Agent     │  │Agent         │ │Agent   │    │
│  └─────┘ └──────┘  └──────────┘  └──────────────┘ └────────┘    │
│    │         │            │              │              │          │
│    └────┬────┴────────────┴──────────────┴──────────────┘          │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              State Machine + Persistence                     │  │
│  │           History • Audit Trail • Finding Cache              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## ✨ Key Features

### 🔍 Intelligent Attack Surface Discovery
- **Domain Enumeration**: Discovers root domains, subdomains, and related assets
- **API Discovery**: Detects OpenAPI/Swagger, GraphQL, and REST endpoints automatically
- **Service Mapping**: Port scanning, fingerprinting, and technology detection
- **Continuous Monitoring**: Real-time alerts on new assets and configuration changes

### 🧠 AI-Powered Vulnerability Analysis
- **LLM Reasoning**: Uses Claude/GPT-4 to analyze vulnerabilities with business context
- **Intelligent Prioritization**: Scores by exploitability, impact, and asset criticality
- **Attack Chain Analysis**: Identifies multi-step vulnerability chains
- **Context Awareness**: Considers security posture and industry standards

### ⚡ Safe Exploitation & Validation
- **Proof-of-Concept Generation**: Automatically creates exploit code
- **Non-Destructive Testing**: Validates without causing damage
- **Approval Workflows**: Critical actions require human sign-off
- **Evidence Collection**: Screenshots, logs, and reproduction instructions

### 📊 Professional Reporting
- **Executive Summaries**: High-level risk overview for leadership
- **Technical Reports**: Detailed findings with reproduction steps and CVSS scores
- **Remediation Guidance**: Actionable recommendations with priority levels
- **Dashboard Visualization**: Real-time metrics and assessment progress

### 🎯 Enterprise-Ready
- **Human Oversight**: Built-in approval workflows at exploitation stage
- **Audit Trail**: Complete logging of all actions and approvals
- **Multi-Channel Alerts**: Slack, PagerDuty, Microsoft Teams, Email
- **Compliance Tracking**: Tracks assessments against frameworks (OWASP, CWE, etc.)

## 🎨 Frontend Dashboard

Modern, professional React dashboard with:

- **Hero Section**: Showcases platform capabilities and value proposition
- **Real-time Metrics**: Live dashboard with assessment progress and findings
- **Search & Filtering**: Live search in findings with severity-based filters
- **Dark Mode**: Premium glassmorphism UI with dark-first design
- **Smooth Animations**: Professional transitions and micro-interactions
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile
- **Accessible**: WCAG compliant with high contrast ratios

**Tech Stack**: React 18 • TypeScript • Tailwind CSS • Vite • Zustand • Lucide Icons

## 🔧 System Components

### Backend (Python/FastAPI)
- **`api.py`**: REST API gateway serving the frontend
- **`project/workflow.py`**: Main orchestration workflow using Temporal
- **`project/run_worker.py`**: Worker process that executes pentesting activities
- **`project/acp.py`**: Agent communication protocol handler

### Frontend (React/TypeScript)
- **`frontend/src/pages/`**: Dashboard, Assessments, Findings, Compliance, Audit Trail
- **`frontend/src/components/`**: Reusable Navigation, Layout, Card components
- **`frontend/src/hooks/`**: Custom hooks for state and API communication
- **`frontend/src/services/`**: API client services

### Temporal Workflows
| Workflow | Purpose |
|----------|---------|
| `MajorProjectWorkflow` | Main pentesting orchestration (discovery → analysis → exploitation → reporting) |
| `ContinuousPentestWorkflow` | Scheduled continuous security testing |
| `DiscoveryWorkflow` | Asset and vulnerability discovery |
| `ExploitationWorkflow` | Safe exploitation with approval gates |

### AI Agents (100+ Activities)
- **Asset Discovery Agent**: Maps attack surface
- **Vulnerability Reasoner**: AI-driven analysis
- **Exploit Generation Agent**: PoC creation and validation
- **Threat Intelligence Agent**: External threat research
- **Reporting Agent**: Professional report generation
- **Verification & Safety Agent**: Approval and risk assessment

## ⚡ Quick Start (Demo)

### Prerequisites
- Python 3.12+
- Node.js 18+
- Git

### 1️⃣ Backend (API)

```bash
cd major_project

# Activate virtual environment
.\venv\Scripts\Activate.ps1  # Windows
# source venv/bin/activate   # Linux/Mac

# Start API server
python -m uvicorn api:app --reload --port 8000
# Server runs on http://localhost:8000
```

### 2️⃣ Frontend (Dashboard)

```bash
cd major_project/frontend
npm install
npm run dev
# Dashboard runs on http://localhost:5173
```

### 3️⃣ View the Demo
1. Open http://localhost:5173 in your browser
2. **Hero Section**: View platform overview with animated shield
3. **Dashboard Tab**: See real-time metrics and security stats
4. **Assessments Tab**: Click "Start Security Assessment" or click any assessment for details
5. **Findings Tab**: View vulnerabilities with live search and filters
6. **Dark Mode**: Toggle theme in top-right corner

## 🛠️ Full Installation

### Prerequisites for Production

- Python 3.12+
- Temporal server
- MongoDB (for history persistence)
- Redis (for streaming)
- Security tools: nmap, subfinder, nuclei, httpx, katana

### Production Deployment

```bash
# Clone the repository
cd major_project

# Install dependencies
pip install -e .

# Set environment variables
export OPENAI_API_KEY="your-api-key"
export TEMPORAL_ADDRESS="localhost:7233"
export MONGODB_URI="mongodb://localhost:27017"

# Run the worker
python -m project.run_worker
```

### Kubernetes Deployment

```bash
# Deploy using Helm
helm install major-project ./chart/major-project \
  --set temporal-worker.env_vars.OPENAI_API_KEY="your-api-key" \
  --set temporal-worker.env_vars.SLACK_WEBHOOK_URL="your-webhook"
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI/OpenRouter API key | Required |
| `OPENAI_BASE_URL` | LLM API base URL | `https://api.openai.com/v1` |
| `OPENAI_MODEL` | LLM model to use | `gpt-4` |
| `TEMPORAL_ADDRESS` | Temporal server address | `localhost:7233` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017` |
| `MONGODB_DATABASE` | Database name | `major_project` |
| `ALLOWED_EMAILS` | Comma-separated allowed user emails | Required |
| `SLACK_WEBHOOK_URL` | Slack webhook for alerts | Optional |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty routing key | Optional |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams webhook | Optional |
| `CONTINUOUS_DISCOVERY_ENABLED` | Enable continuous monitoring | `true` |
| `CONTINUOUS_DISCOVERY_INTERVAL_HOURS` | Scan interval | `24` |

### Alerting Configuration

Configure alerting channels in the Helm values:

```yaml
temporal-worker:
  env_vars:
    SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/..."
    PAGERDUTY_ROUTING_KEY: "your-routing-key"
    TEAMS_WEBHOOK_URL: "https://outlook.office.com/webhook/..."
```

## 🔒 Security Considerations

### Human Oversight

Major Project is designed with human oversight at critical points:

1. **Approval Required**: Exploitation requires explicit user approval
2. **Scope Limits**: Testing is limited to approved targets
3. **Safe Mode**: Non-destructive testing by default
4. **Audit Trail**: All actions are logged

### Access Control

- Email-based access control via `ALLOWED_EMAILS`
- API key authentication for agent communication
- Kubernetes RBAC for deployment security

### Responsible Use

⚠️ **Important**: Only use Major Project against systems you own or have explicit authorization to test. Unauthorized penetration testing is illegal.

## 📊 Usage Examples

### Starting a Pentest

```python
# Via Temporal workflow
from temporalio.client import Client

client = await Client.connect("localhost:7233")

# Start the workflow
handle = await client.start_workflow(
    "MajorProjectWorkflow",
    id="pentest-example-com",
    task_queue="red-cell-queue",
)

# Send target scope
await handle.signal("user_input", {
    "type": "target_scope",
    "domains": ["example.com"],
    "scope": "*.example.com",
})
```

### Approving Exploitation

```python
# Approve exploitation of findings
await handle.signal("approval", {
    "approved": True,
    "findings": ["finding-1", "finding-2"],
    "approver": "security-team@example.com",
})
```

## 📈 Monitoring

### Metrics

Major Project exposes metrics for monitoring:

- `major_project_discoveries_total`: Total assets discovered
- `major_project_vulnerabilities_found`: Vulnerabilities by severity
- `major_project_exploits_executed`: Exploitation attempts
- `major_project_scan_duration_seconds`: Scan duration

### Logging

Structured logging with levels:

```python
logger.info("Starting discovery", extra={
    "target": "example.com",
    "scan_type": "full",
})
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is part of the AgentEx platform. See the main repository for license information.

## 🆘 Support

For issues and questions:

1. Check the [documentation](./docs/)
2. Open a GitHub issue
3. Contact the security team

---

## 📋 Project Status

✅ **v1.0 Demo Ready**
- Frontend dashboard fully functional with premium UI/UX
- REST API gateway working with mock data
- Temporal workflow orchestration framework in place
- Safety and approval workflows implemented
- Professional reporting ready
- Dark mode and responsive design complete

**Built with ❤️ using Temporal • FastAPI • React 18 • TypeScript • Tailwind CSS**
