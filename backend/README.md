# spvm3-SentinelAI - Backend

The backend of **spvm3-SentinelAI** is an AI-based cyber threat early warning and autonomous SOC triage REST API built with **FastAPI**. It handles real-time log ingestion, Model v3 multi-stage attack detection, AI anomaly scoring, forensic data-theft blast radius analysis, CERT-In compliance playbooks, and simulated incident containment.

## 🛠️ Technologies
- **Python 3.10+**
- **FastAPI & Uvicorn** for high-throughput asynchronous API routing
- **SQLite** (`sentinel.db`) for ACID relational data and audit trails
- **scikit-learn** (Model v3 Anomaly & Threat Classifier trained on CICIDS2017 & Loghub)
- **Forensic Engine** for data exfiltration attribution, volume quantification, and CERT-In reporting

---

## ⚙️ Setup and Running

### Option 1: Windows (PowerShell or Command Prompt)
Run the following commands in your terminal:
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app:app --reload --port 8000
```

### Option 2: macOS / Linux
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app:app --reload --port 8000
```

> [!TIP]
> Once running, access the interactive OpenAPI / Swagger documentation at:
> **http://localhost:8000/docs** or **http://127.0.0.1:8000/docs**

---

## 📁 Core Architecture

- **`app.py`**: Main FastAPI server exposing endpoints for event ingestion, alerts, AI forensic assistant, chatbot, and containment.
- **`assistant.py`**: Forensic analysis engine answering *"Did they steal the data?"*, computing compromised assets/PII, estimating stolen bytes, attributing MITRE techniques, and generating 6-hour CERT-In compliance notices.
- **`detector.py`**: Heuristic and machine-learning threat detection engine scoring risk and mapping alerts to MITRE ATT&CK tactics.
- **`train_dataset_pipeline.py`**: Pipeline supporting real **CICIDS2017** and **Loghub** formats. Evaluates and exports production **Model v3** (`models/model_v3.pkl`).
- **`db.py`**: SQLite database initialization, schemas, and connection contexts.
- **`generate_logs.py`**: Synthetic telemetry generator simulating realistic multi-stage brute-force, SQL injection, DoS, and data exfiltration campaigns.

---

## 🔌 API Endpoints Reference

### Core SOC Triage & Monitoring
- `GET /api/alerts` — Retrieve all detected alerts (optional filter: `?severity=Critical`).
- `GET /api/stats` — Retrieve aggregate statistics (event volume, severity breakdown, top risky IPs).
- `PATCH /api/alerts/{aid}/status` — Update investigation status (`Investigating`, `Resolved`, `False Positive`).
- `POST /api/alerts/{aid}/respond` — Execute **simulated** containment (quarantine host / block IP).
- `GET /api/audit` — Retrieve audit trail log of SOC actions and system interventions.

### Machine Learning & Forensics
- `GET /api/model_info` — Retrieve active model metadata (Model v3, precision/recall, training dataset).
- `POST /api/assistant/analyze` — Run full forensic investigation answering data theft likelihood, blast radius, compromised assets, and CERT-In advisory.
- `POST /api/chat` — Conversational SOC assistant providing interactive guidance on alerts and incident response.

### Ingestion & Simulation
- `POST /api/demo/generate` — Seed synthetic multi-stage cyber attack telemetry.
- `POST /api/analyze` — Execute detection pipeline on ingested raw events.
- `POST /api/upload` — Ingest custom CSV log files for automated triage.

