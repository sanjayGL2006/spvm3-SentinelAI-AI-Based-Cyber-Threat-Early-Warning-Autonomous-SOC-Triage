# SentinelAI — Product & Technical Requirements Document (PRD & TRD)
**Version:** 1.0 (Hackathon Edition)  
**Author / Owner:** Sanjay G L  
**Status Key:**  
- `[Built]` Implemented and verified on sample/synthetic data  
- `[Planned]` Scheduled for subsequent hackathon evaluation phases  
- `[Future]` Post-hackathon enterprise roadmap  

---

## Part 1: Product Requirements Document (PRD)

### 1. Vision & Executive Summary
**Vision:** Give small government IT teams early awareness of cyber attacks without needing a large, costly 24/7 Security Operations Centre (SOC).

SentinelAI is an AI-based cyber threat early warning and autonomous SOC triage tool designed specifically for resource-constrained public sector IT teams. It ingests network, authentication, and application logs, detects anomalous and malicious behavior using a hybrid detection engine, scores risk from 0 to 100, explains *why* each alert fired in human-readable terms, and provides one-click simulated containment with an audit trail and CERT-In-ready PDF reporting.

### 2. Goals
- **Product Goal:** Cut the time from *"an attack starts"* to *"an analyst understands and acts"* from hours to under 60 seconds.
- **Hackathon Goal:** Deliver an honest, robust, demo-ready prototype that finishes in the **Top 6** of the competition.

---

### 3. Problem Statement
1. **Log Deluge vs. Analyst Shortage:** Government IT departments collect millions of events daily across firewalls, gateways, and auth servers, but often have only 1–2 generalist IT staff to triage them.
2. **Alert Fatigue & Noise:** Traditional SIEM and IDS rules generate hundreds of low-fidelity alerts daily. Analysts cannot quickly determine which alert is most dangerous or why it triggered.
3. **Delayed Detection:** Critical attacks—such as password spraying, SQL injection, API flooding, and data exfiltration—are often discovered weeks after data loss has already occurred.

---

### 4. User Personas & Core Needs

| Persona | Role | Core Needs |
|---|---|---|
| **SOC / IT Analyst** *(Primary)* | Frontline responder reviewing daily telemetry | • A ranked queue answering: *What is most dangerous?*<br>• Plain-language explanations: *Why was it flagged?*<br>• Direct remediation steps: *What should I do now?*<br>• One-click simulated containment & state tracking. |
| **IT Manager / CISO** *(Secondary)* | Security leadership overseeing compliance | • High-level severity counts and risk distribution.<br>• Exportable PDF incident reports for compliance.<br>• Defensible audit trail of actions taken & CERT-In reporting reminders. |
| **System Administrator** | DevOps / IT Admin deploying the tool | • Zero-friction installation (single-command setup).<br>• Resilient CSV ingestion with schema validation and error tolerance.<br>• Configurable detection sensitivity thresholds. |
| **Hackathon Judge** | Evaluator measuring innovation and execution | • A high-impact 5-minute live demo showing attack detection, instant triage, explainability, containment, and report generation. |

---

### 5. Project Scope

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SENTINELAI SCOPE MATRIX                         │
├──────────────────────────────────┬─────────────────────────────────────┤
│      IN SCOPE (HACKATHON)        │     OUT OF SCOPE (HACKATHON)        │
├──────────────────────────────────┼─────────────────────────────────────┤
│ • CSV log upload & validation    │ • Real firewall / SDN integration   │
│ • Synthetic 4h multi-attack logs │   (containment stays simulated)     │
│ • 5-min rolling window features  │ • Production SIEM plugins (Splunk)  │
│ • Rules + IsolationForest + XGB  │ • Multi-tenant cloud SaaS hosting   │
│ • 0-100 Risk score & Severities  │ • Mobile applications               │
│ • Plain-language explanations    │ • Role-Based Access Control (RBAC)  │
│ • MITRE ATT&CK technique mapping │ • Black-box deep learning models    │
│ • Interactive SOC Dashboard UI   │ • Automated destructive host wiping │
│ • Status workflow & Audit log    │ • Enterprise SSO / SAML 2.0         │
│ • PDF incident export (ReportLab)│                                     │
└──────────────────────────────────┴─────────────────────────────────────┘
```

---

### 6. Feature Requirements (MoSCoW Framework)

#### Must Have (P0 — Core Hackathon Deliverables)
- `[Built]` **M1: CSV Log Ingestion & Validation** — Accepts `.csv` logs up to 20MB, validates schema (`ts`, `source`, `src_ip`), and safely skips malformed rows.
- `[Built]` **M2: Synthetic Log Generator** — Generates 4 hours of baseline enterprise traffic injected with 5 realistic attack scenarios (Brute Force, Port Scan, SQLi, Request Flood, Data Exfiltration).
- `[Built]` **M3: Time-Window Feature Engineering** — Computes rolling 5-minute statistical windows per source IP (request rates, error counts, distinct destination ports, off-hours byte spikes).
- `[Built]` **M4: Rule-Based Detection Engine** — Deterministic detection of known attack signatures with zero false-positives on standard threat patterns.
- `[Built]` **M5: Unsupervised Anomaly Detection** — scikit-learn `IsolationForest` identifying novel behavioral outliers without requiring historical attack labels.
- `[Built]` **M6: Calibrated 0–100 Risk Scoring** — Transparent scoring formula combining rule hits, anomaly scores, and asset criticality tiers into 4 severities (`Critical`, `High`, `Medium`, `Low`).
- `[Built]` **M7: Plain-Language Alert Explanations** — Every alert itemizes the exact telemetry metrics and thresholds that triggered the alert.
- `[Built]` **M8: MITRE ATT&CK Mapping & Playbooks** — Direct association with MITRE techniques (e.g., T1110, T1190, T1048) and an actionable analyst checklist.
- `[Built]` **M9: High-Contrast SOC Triage Dashboard** — Responsive interface with clickable severity filter tiles, large-score alert queue, circular SVG risk rings, and top risky sources bar chart.
- `[Built]` **M10: Alert Lifecycle & Simulated Containment** — Segmented status control (`New`, `Investigating`, `Contained`, `Resolved`), dynamic block/isolate button, and SQLite-backed audit log.
- `[Built]` **M11: Exportable Incident Reports** — Server-side PDF report generation (`ReportLab`) summarizing incidents, evidence, and regulatory CERT-In guidance.

#### Should Have (P1 — Competition Differentiators)
- `[Planned]` **S1: Real-Dataset Evaluation (CICIDS2017 / Loghub)** — Model evaluation benchmarks reporting Precision, Recall, F1-Score, ROC-AUC, FPR, and Confusion Matrix.
- `[Planned]` **S2: Multi-Stage Early Warning Prediction** — Markov / sequence-based stage prediction anticipating kill-chain progression (e.g. *Reconnaissance → Brute Force → Exfiltration*) before final impact.

#### Could Have (P2 — Stretch Goals)
- `[Planned]` **C1: Multi-Alert Incident Correlation** — Aggregating multiple alerts sharing common IP/subnet/user within a time window into unified incident tickets.
- `[Planned]` **C2: Local Feature Attribution (SHAP)** — Displaying the top 5 model feature weights directly on the alert triage view.
- `[Planned]` **C3: GenAI Incident Briefings** — Prompt-injection safe narrative summaries generated via LLM API.

---

### 7. User Stories

1. **Fast Alert Ingestion:**  
   *As an analyst,* I want to upload a CSV log file and see prioritised alerts within seconds so that I can begin triage immediately without waiting for batch processing.
2. **Immediate Threat Identification:**  
   *As an analyst,* I want to view a visual indicator of risk (0–100 score and circular risk ring) so that I instantly know which alert is most dangerous.
3. **Transparent Reasoning:**  
   *As an analyst,* I want to read human-readable bullet points detailing *why* an alert was flagged so that I can verify its legitimacy without manually inspecting raw log rows.
4. **Actionable Response:**  
   *As an analyst,* I want a structured checklist of recommended response steps and a one-click simulated containment button so that I know what to do and can record the containment action immediately.
5. **Auditable Reporting:**  
   *As an IT manager,* I want to download a PDF report containing all telemetry evidence and audit logs so that our department satisfies government incident disclosure mandates.

---

## Part 2: Technical Requirements Document (TRD)

### 1. System Architecture

SentinelAI follows a modular three-tier architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SENTINELAI ARCHITECTURE                         │
└────────────────────────────────────────────────────────────────────────┘

  [ Client Tier ]
    ├── Standalone HTML SOC Dashboard (Zero build step, inline CSS/JS)
    └── React 18 + TypeScript SPA (Vite)
            │  ▲
   REST API │  │ Server-Sent Events (SSE /api/stream)
            ▼  │
  [ Application Tier: FastAPI (Python 3.11) ]
    ├── /api/upload       ── CSV Ingest & Schema Validation
    ├── /api/demo         ── Synthetic 4h Attack Scenario Replay
    ├── /api/alerts       ── Prioritised Alert Queue & Triage
    ├── /api/stats        ── SOC Metrics & Risky Sources
    ├── /api/respond      ── Simulated Containment Dispatcher
    ├── /api/reports/pdf  ── ReportLab PDF Document Engine
    │
    ▼
  [ Detection & Analytics Pipeline (detector.py) ]
    ├── 1. Rolling 5-Minute Window Feature Extraction (Pandas/NumPy)
    ├── 2. Deterministic Heuristic Rules (Explainable baseline)
    ├── 3. Unsupervised IsolationForest (Novel anomaly detection)
    ├── 4. Supervised XGBoost Classifier (Trained pattern verification)
    └── 5. Composite Risk Scorer (0-100) + Asset Criticality Weighting
            │
            ▼
  [ Storage Tier: SQLite (sentinel.db) ]
    ├── Table: events     (Indexed by ts, src_ip)
    ├── Table: alerts     (Indexed by severity, risk, status)
    ├── Table: blocklist  (Simulated edge/host containment list)
    └── Table: audit_log  (Immutable log of analyst triage actions)
```

---

### 2. Technology Choices & Justification

| Architectural Layer | Selected Technology | Why Chosen Over Alternatives | Considered Alternatives |
|---|---|---|---|
| **Backend Framework** | **Python 3.11 + FastAPI** | Native async concurrency, automatic OpenAPI documentation, high developer velocity, and direct Python data science ecosystem integration. | Flask, Django, Express.js |
| **Primary Database** | **SQLite (with WAL mode & indexes)** | Zero configuration, single-file distribution, portable across operating systems, more than fast enough for hackathon demo scale. | PostgreSQL, MongoDB |
| **Anomaly Detection** | **scikit-learn (Isolation Forest)** | Unsupervised, requires no ground-truth attack labels, lightweight inference latency (<20ms). | Autoencoders, One-Class SVM, Local Outlier Factor |
| **Supervised ML** | **XGBoost / RandomForest** | State-of-the-art accuracy on tabular log telemetry, resilient against feature collinearity, fast training. | Deep Neural Networks, LightGBM |
| **Explainability** | **Telemetry Evidence Rules + Feature Gain** | 100% deterministic, easy for non-ML experts to understand, zero latency penalty during live triage. | SHAP TreeExplainer, LIME |
| **Frontend UI** | **Self-contained SOC Dashboard HTML + React/TS** | Immediate zero-install standalone demo execution for judges, accompanied by a typed React production interface. | Streamlit, Gradio, Plain Vue |
| **Report Generation** | **ReportLab (Python)** | Programmatic vector PDF generation, custom SOC headers, data tables, and print formatting. | WeasyPrint, PDFKit |

---

### 3. Data Schema (SQLite)

```sql
-- 1. Ingested Log Events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                -- ISO-8601 UTC timestamp
    source TEXT NOT NULL,            -- 'auth', 'web', 'network', 'firewall'
    src_ip TEXT NOT NULL,            -- Source IPv4 address
    dst_ip TEXT,                     -- Destination IPv4 address
    dst_port INTEGER,                -- Destination port number
    username TEXT,                   -- Targeted or authenticating user
    action TEXT,                     -- 'login', 'request', 'connect', etc.
    status TEXT,                     -- 'success', 'failed', 'blocked'
    bytes_out INTEGER DEFAULT 0,     -- Outbound payload size in bytes
    url TEXT,                        -- Request path or URI
    message TEXT                     -- Raw syslog / application message
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);

-- 2. Generated Threat Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    threat TEXT NOT NULL,            -- e.g. 'Brute Force', 'SQL Injection'
    severity TEXT NOT NULL,          -- 'Critical', 'High', 'Medium', 'Low'
    risk INTEGER NOT NULL,           -- 0 to 100
    src_ip TEXT NOT NULL,
    target TEXT,                     -- Formatted destination target
    confidence REAL NOT NULL,        -- Model confidence (0.0 to 1.0)
    anomaly_score REAL NOT NULL,     -- Isolation forest anomaly metric
    reasons TEXT NOT NULL,           -- JSON array of plain-language strings
    mitre TEXT NOT NULL,             -- JSON array of MITRE technique IDs
    actions TEXT NOT NULL,           -- JSON array of recommended actions
    status TEXT DEFAULT 'New'        -- 'New', 'Investigating', 'Contained', 'Resolved'
);
CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk DESC);

-- 3. Simulated Blocklist
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TEXT NOT NULL
);

-- 4. Audit Trail
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,            -- 'STATUS_CHANGE', 'CONTAIN_SIMULATED', 'REPORT_EXPORT'
    details TEXT NOT NULL
);
```

---

### 4. Detection Logic & Scoring Formula

1. **5-Minute Rolling Aggregation per Source IP:**
   - $N_{req}$: Total request count
   - $N_{fail}$: Failed authentication count
   - $U_{ports}$: Count of distinct destination ports accessed
   - $B_{out}$: Total outbound byte transfer
   - $R_{err}$: Ratio of HTTP 4xx/5xx responses
   - $H_{off}$: Off-hours boolean flag (local hour $\in [22, 05]$)

2. **Deterministic Attack Rules:**
   - **Brute Force:** $N_{fail} \ge 20$ within 60s $\rightarrow$ Rule Risk = 85
   - **Port Scan:** $U_{ports} \ge 25$ within 60s $\rightarrow$ Rule Risk = 75
   - **SQL Injection:** SQL syntax signatures (`UNION`, `SELECT`, `OR 1=1`) in URL/payload $\rightarrow$ Rule Risk = 90
   - **Request Flood (DoS):** $N_{req} \ge 1,000$ within 60s $\rightarrow$ Rule Risk = 85
   - **Data Exfiltration:** $B_{out} \ge 50\,\text{MB}$ and $H_{off} = \text{true}$ $\rightarrow$ Rule Risk = 80

3. **Composite Risk Score ($0 \le R \le 100$):**
   $$R = \min\left(100, \; \text{round}\left(w_{rule} \cdot R_{rule} + w_{if} \cdot S_{if} + w_{xgb} \cdot P_{xgb} + A_{crit}\right)\right)$$
   Where:
   - $w_{rule} = 0.55$: Weight of rule engine
   - $w_{if} = 0.25$: Weight of Isolation Forest anomaly score ($S_{if} \in [0, 100]$)
   - $w_{xgb} = 0.20$: Weight of XGBoost threat probability ($P_{xgb} \in [0, 100]$)
   - $A_{crit} \in [0, 15]$: Asset criticality bonus (Tier 1 core assets add $+10$ to $+15$)

4. **Severity Thresholds:**
   - **Critical:** $R \ge 90$
   - **High:** $70 \le R \le 89$
   - **Medium:** $40 \le R \le 69$
   - **Low:** $0 \le R \le 39$

---

### 5. Verification & Testing Strategy

| Verification Dimension | Test Strategy | Status |
|---|---|---|
| **CSV Validation** | Tests malformed headers, missing required columns (`ts`, `source`, `src_ip`), oversized payloads (>20MB), and non-CSV file extensions. | `[Built & Tested]` |
| **Detection Coverage** | Validates all 5 injected attack vectors trigger alerts with severity $\ge \text{High}$. | `[Built & Tested]` |
| **Scoring Consistency** | Asserts risk scores remain strictly within $[0, 100]$ and monotonic with threat velocity. | `[Built & Tested]` |
| **Containment Idempotency** | Prevents duplicate containment actions; verifies host isolation vs. external IP blocking strings. | `[Built & Tested]` |
| **UI Standalone Fidelity** | Verifies zero-dependency HTML dashboard renders accurately with dark/light mode and interactive controls. | `[Built & Tested]` |
| **Real Dataset Metrics** | Evaluates model precision, recall, and false-positive rates on CICIDS2017 subset. | `[Planned: Phase 20]` |

---

### 6. Honest Limitations & Disclaimers

1. **Synthetic Demo Calibration:** Thresholds in the demo generator are optimized for clear demonstration of typical attack scenarios. Real production deployments require threshold calibration against environment baselines.
2. **Simulated Containment:** All block and isolation actions write to SQLite and display confirmation toasts; **they do not alter physical firewalls, iptables, or network hardware**.
3. **Model Interpretability:** Confidence values are blended heuristics combining rule certainty and model output probabilities, not calibrated frequentist probabilities.
