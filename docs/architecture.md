# Major-Project AI Pentester - Architecture Diagrams

This document contains Mermaid diagrams illustrating the architecture of the Major-Project AI Pentester agent.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Client["Client Layer"]
        UI[Web UI / API Client]
    end

    subgraph Agent["Major-Project Agent"]
        direction TB
        SM[State Machine<br/>MajorProjectStateMachine]

        subgraph Workflows["Temporal Workflows"]
            direction LR
            DW[Discovery<br/>Workflow]
            AW[Analysis<br/>Workflow]
            EW[Exploitation<br/>Workflow]
            RW[Reporting<br/>Workflow]
        end

        subgraph Activities["Activities"]
            direction TB
            DA[Discovery<br/>Activities]
            AA[Analysis<br/>Activities]
            EA[Exploitation<br/>Activities]
            RA[Reporting<br/>Activities]
        end
    end

    subgraph External["External Services"]
        LLM[LLM API<br/>OpenAI/Claude]
        DB[(MongoDB<br/>Attack Surface History)]
        Target[Target<br/>Systems]
    end

    UI --> SM
    SM --> DW
    SM --> AW
    SM --> EW
    SM --> RW

    DW --> DA
    AW --> AA
    EW --> EA
    RW --> RA

    DA --> Target
    EA --> Target
    AA --> LLM
    EA --> LLM
    RA --> LLM
    DA --> DB
    RA --> DB
```

## State Machine Flow

```mermaid
stateDiagram-v2
    [*] --> INITIALIZING: Start

    INITIALIZING --> DISCOVERING_ASSETS: Initialize Complete
    INITIALIZING --> FAILED: Error

    DISCOVERING_ASSETS --> MAPPING_ATTACK_SURFACE: Assets Discovered
    DISCOVERING_ASSETS --> FAILED: Error

    MAPPING_ATTACK_SURFACE --> ANALYZING_VULNERABILITIES: Surface Mapped
    MAPPING_ATTACK_SURFACE --> FAILED: Error

    ANALYZING_VULNERABILITIES --> PRIORITIZING_TARGETS: Vulns Identified
    ANALYZING_VULNERABILITIES --> FAILED: Error

    PRIORITIZING_TARGETS --> GENERATING_EXPLOITS: Targets Prioritized
    PRIORITIZING_TARGETS --> FAILED: Error

    GENERATING_EXPLOITS --> VERIFYING_EXPLOITS: Exploits Generated
    GENERATING_EXPLOITS --> FAILED: Error

    VERIFYING_EXPLOITS --> GENERATING_REPORT: Exploits Verified
    VERIFYING_EXPLOITS --> FAILED: Error

    GENERATING_REPORT --> COMPLETED: Report Generated
    GENERATING_REPORT --> FAILED: Error

    COMPLETED --> [*]
    FAILED --> [*]
```

## Discovery Workflow

```mermaid
flowchart TB
    subgraph Discovery["Discovery Workflow"]
        Start([Start]) --> DD[Discover Domains]
        DD --> DS[Discover Subdomains]
        DS --> API[Discover APIs]
        API --> SVC[Discover Services]
        SVC --> TECH[Detect Technologies]
        TECH --> SAVE[Save Snapshot]
        SAVE --> DETECT[Detect Changes]
        DETECT --> ALERT{New<br/>Exposures?}
        ALERT -->|Yes| NOTIFY[Send Alert]
        ALERT -->|No| End([End])
        NOTIFY --> End
    end

    subgraph Activities["Activities Used"]
        A1[discover_domains_activity]
        A2[discover_subdomains_activity]
        A3[discover_apis_activity]
        A4[discover_services_activity]
        A5[detect_technologies_activity]
        A6[save_attack_surface_snapshot_activity]
        A7[detect_attack_surface_changes_activity]
        A8[send_change_detection_alert_activity]
    end

    DD -.-> A1
    DS -.-> A2
    API -.-> A3
    SVC -.-> A4
    TECH -.-> A5
    SAVE -.-> A6
    DETECT -.-> A7
    NOTIFY -.-> A8
```

## Analysis Workflow

```mermaid
flowchart TB
    subgraph Analysis["Analysis Workflow"]
        Start([Start]) --> SCAN[Vulnerability Scanning]
        SCAN --> AI[AI Vulnerability Reasoning]
        AI --> ZERO[Zero-Day Discovery]
        ZERO --> CHAIN[Attack Chain Analysis]
        CHAIN --> PRIO[Prioritize Targets]
        PRIO --> End([End])
    end

    subgraph AIReasoning["AI Reasoning Engine"]
        direction TB
        LLM1[Analyze Patterns]
        LLM2[Identify Anomalies]
        LLM3[Reason About Impact]
        LLM4[Generate Hypotheses]
    end

    subgraph ZeroDay["Zero-Day Discovery"]
        direction TB
        Z1[Behavioral Analysis]
        Z2[Pattern Matching]
        Z3[Anomaly Detection]
        Z4[Novel Attack Vectors]
    end

    AI --> AIReasoning
    ZERO --> ZeroDay
```

## Exploitation Workflow

```mermaid
flowchart TB
    subgraph Exploitation["Exploitation Workflow"]
        Start([Start]) --> GEN[Generate Exploits]
        GEN --> CREATIVE[Creative Payload Generation]
        CREATIVE --> MUTATE[Payload Mutation]
        MUTATE --> CHAIN[Chain PoC Generation]
        CHAIN --> VERIFY[Verify Exploits]
        VERIFY --> End([End])
    end

    subgraph PayloadGen["LLM Payload Generation"]
        direction TB
        P1[SQLi Payloads]
        P2[XSS Payloads]
        P3[SSRF Payloads]
        P4[Path Traversal]
        P5[Command Injection]
        P6[Auth Bypass]
    end

    subgraph Mutation["Mutation Engine"]
        direction TB
        M1[URL Encoding]
        M2[Unicode Variations]
        M3[Case Variations]
        M4[Comment Insertion]
        M5[Null Byte Injection]
    end

    CREATIVE --> PayloadGen
    MUTATE --> Mutation
```

## Reporting Workflow

```mermaid
flowchart TB
    subgraph Reporting["Reporting Workflow"]
        Start([Start]) --> EXEC[Executive Summary]
        EXEC --> TECH[Technical Report]
        TECH --> FIND[Generate Findings]
        FIND --> TREND[Trend Analysis]
        TREND --> DASH[Dashboard Data]
        DASH --> End([End])
    end

    subgraph Reports["Report Types"]
        direction TB
        R1[Executive Summary<br/>Business Impact]
        R2[Technical Report<br/>Detailed Findings]
        R3[Remediation Guide<br/>Fix Instructions]
        R4[Trend Report<br/>Historical Analysis]
    end

    EXEC --> R1
    TECH --> R2
    FIND --> R3
    TREND --> R4
```

## Agentic Pentest Loop

```mermaid
flowchart TB
    subgraph AgentLoop["AI Agent Loop"]
        direction TB
        OBS[OBSERVE<br/>Current State]
        THINK[THINK<br/>LLM Reasoning]
        ACT[ACT<br/>Execute Tool]
        LOOP{Continue?}

        OBS --> THINK
        THINK --> ACT
        ACT --> LOOP
        LOOP -->|Yes| OBS
        LOOP -->|No| END([Finish])
    end

    subgraph Tools["Available Tools"]
        direction TB
        T1[crawl_endpoint]
        T2[test_sqli]
        T3[test_xss]
        T4[test_ssrf]
        T5[test_path_traversal]
        T6[test_cmdi]
        T7[comprehensive_scan]
        T8[analyze_attack_chains]
        T9[report_finding]
    end

    subgraph Context["Agent Context"]
        direction TB
        C1[Discovered Endpoints]
        C2[Parameters Found]
        C3[Technologies Detected]
        C4[Findings So Far]
        C5[Actions Taken]
    end

    ACT --> Tools
    OBS --> Context
    THINK -.-> LLM[LLM API]
```

## Data Flow

```mermaid
flowchart LR
    subgraph Input["Input"]
        TARGET[Target URL]
        SCOPE[Scope Definition]
        CONFIG[Configuration]
    end

    subgraph Processing["Processing"]
        direction TB
        DISC[Discovery]
        ANAL[Analysis]
        EXPL[Exploitation]
        REPO[Reporting]
    end

    subgraph Storage["Storage"]
        DB[(MongoDB)]
        MEM[In-Memory State]
    end

    subgraph Output["Output"]
        FIND[Findings]
        CHAIN[Attack Chains]
        REPORT[Reports]
        ALERT[Alerts]
    end

    TARGET --> DISC
    SCOPE --> DISC
    CONFIG --> DISC

    DISC --> ANAL
    ANAL --> EXPL
    EXPL --> REPO

    DISC --> DB
    ANAL --> MEM
    EXPL --> MEM
    REPO --> DB

    REPO --> FIND
    REPO --> CHAIN
    REPO --> REPORT
    DISC --> ALERT
```

## Component Dependencies

```mermaid
flowchart TB
    subgraph Core["Core Components"]
        SM[State Machine]
        WF[Workflows]
        ACT[Activities]
    end

    subgraph Infrastructure["Infrastructure"]
        TEMP[Temporal Server]
        MONGO[MongoDB]
        K8S[Kubernetes]
    end

    subgraph External["External APIs"]
        LLM[LLM API<br/>OpenAI/Claude]
        DNS[DNS Services]
        CERT[Certificate APIs]
    end

    subgraph Libraries["Key Libraries"]
        AGENTEX[agentex-sdk]
        OPENAI[openai-python]
        MOTOR[motor<br/>async MongoDB]
        HTTPX[httpx<br/>HTTP client]
    end

    SM --> TEMP
    WF --> TEMP
    ACT --> TEMP

    ACT --> MONGO
    ACT --> LLM
    ACT --> DNS
    ACT --> CERT

    SM --> AGENTEX
    ACT --> OPENAI
    ACT --> MOTOR
    ACT --> HTTPX

    TEMP --> K8S
    MONGO --> K8S
```

## Vulnerability Testing Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant LLM as LLM API
    participant Target as Target System
    participant UI as User Interface

    Agent->>LLM: Generate creative payloads
    LLM-->>Agent: Context-aware payloads
    Agent->>UI: Display generated payloads

    loop For each payload
        Agent->>Target: Send test request
        Target-->>Agent: Response
        Agent->>Agent: Analyze response

        alt Vulnerability Found
            Agent->>UI: Alert: Vulnerability detected!
            Agent->>Agent: Generate PoC
            Agent->>UI: Display reproduction steps
        end
    end

    Agent->>LLM: Analyze attack chains
    LLM-->>Agent: Chain analysis
    Agent->>UI: Display attack chains
```

## Deployment Architecture

```mermaid
flowchart TB
    subgraph K8s["Kubernetes Cluster"]
        subgraph RedCell["Major-Project Namespace"]
            WORKER[Temporal Worker<br/>Pod]
            CONFIG[ConfigMap]
            SECRET[Secrets]
        end

        subgraph Temporal["Temporal Namespace"]
            SERVER[Temporal Server]
            FRONTEND[Temporal Frontend]
        end

        subgraph Data["Data Namespace"]
            MONGO[(MongoDB)]
        end
    end

    subgraph External["External"]
        LLM[LLM API]
        TARGETS[Target Systems]
    end

    WORKER --> SERVER
    WORKER --> MONGO
    WORKER --> LLM
    WORKER --> TARGETS

    CONFIG --> WORKER
    SECRET --> WORKER
```

## Security Considerations

```mermaid
flowchart TB
    subgraph Security["Security Controls"]
        direction TB

        subgraph Auth["Authentication"]
            API_KEY[API Key Management]
            SECRETS[Kubernetes Secrets]
        end

        subgraph Scope["Scope Control"]
            WHITELIST[Target Whitelist]
            BLACKLIST[Excluded Paths]
            RATE[Rate Limiting]
        end

        subgraph Safety["Safety Measures"]
            NON_DESTRUCT[Non-Destructive Tests]
            LOGGING[Comprehensive Logging]
            AUDIT[Audit Trail]
        end
    end

    subgraph Agent["Major-Project Agent"]
        WORKER[Worker]
    end

    Auth --> WORKER
    Scope --> WORKER
    Safety --> WORKER
```

---

## Legend

| Symbol | Meaning |
|--------|---------|
| Rectangle | Process/Component |
| Diamond | Decision |
| Cylinder | Database |
| Rounded Rectangle | Start/End |
| Dashed Line | Reference/Dependency |
| Solid Line | Data Flow |

## Notes

1. **State Machine**: Controls the overall workflow progression
2. **Workflows**: Temporal workflows that orchestrate activities
3. **Activities**: Individual units of work (discovery, testing, reporting)
4. **LLM Integration**: AI-powered payload generation and analysis
5. **Storage**: MongoDB for persistence, in-memory for runtime state