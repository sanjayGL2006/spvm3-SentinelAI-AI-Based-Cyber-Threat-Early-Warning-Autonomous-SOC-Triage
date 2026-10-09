# spvm3-SentinelAI — AI-Based Cyber Threat Early Warning & Autonomous SOC Triage

**spvm3-SentinelAI** is an advanced cyber threat early warning and autonomous SOC triage platform designed for government and enterprise IT teams. It detects anomalous and malicious patterns across network, authentication, and web logs, assigns calibrated 0–100 threat severity scores, maps attacks to MITRE ATT&CK techniques, provides human-readable explanations, and answers the critical forensic question: *"Did they steal the data?"* with one-click simulated containment and CERT-In-ready audit trails.

---

## 🚀 Tech Stack

- **Backend**: Python 3.11 + FastAPI, SQLite (WAL mode with indexed telemetry), scikit-learn (IsolationForest), XGBoost (Ensemble v3).
- **Frontend / Dashboard**: 
  - Self-contained SOC Triage Dashboard ([`sentinelai_dashboard.html`](./sentinelai_dashboard.html)) with zero build dependencies, inline CSS/JS, Manrope & JetBrains Mono typography, dark/light themes.
  - React 18 + TypeScript + Vite SPA.
- **AI & Analytics**: Deterministic Heuristics + Isolation Forest + XGBoost Classifier + Forensic Data Theft Agent.
- **Reporting & CI/CD**: ReportLab PDF exporter, automated GitHub Actions pipeline ([`.github/workflows/ci.yml`](./.github/workflows/ci.yml)).

---

## 📁 Project Structure

```
sentinelai/
├── backend/
│   ├── app.py                      # FastAPI REST & streaming endpoints
│   ├── assistant.py                # AI Cyber Fraud & Data Theft Forensic Agent + Chatbot
│   ├── db.py                       # SQLite schema (events, alerts, blocklist, audit_log)
│   ├── detector.py                 # Hybrid detection engine (Rules + IsolationForest + XGBoost)
│   ├── generate_logs.py            # Multi-attack synthetic log generator
│   ├── ingest.py                   # Deduplication batch ingestion & SSE broadcaster
│   ├── train_dataset_pipeline.py   # Training pipeline for CICIDS2017 & Loghub datasets
│   ├── models/                     # Saved XGBoost models (model_v3.pkl) and metrics
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── src/                        # React + TypeScript source code
│   └── package.json                # Frontend package configuration
├── .github/workflows/ci.yml        # Automated CI/CD test, lint & build pipeline
├── sentinelai_dashboard.html       # Standalone SOC Triage Dashboard & AI Chatbot UI
├── SentinelAI_Pitch_Deck.pptx      # Official PowerPoint Presentation Pitch Deck
├── PITCH_DECK.md                   # Presentation slides outline & script
├── PRD_TRD.md                      # Comprehensive Product & Technical Requirements
└── README.md                       # Project documentation
```

---

## ⚙️ Quick Start

### 1. Launch the Self-Contained SOC Dashboard (Immediate Demo)
The interactive SOC triage dashboard and AI assistant require **no npm install or build step**. Simply open it in your browser:
- Double-click [`sentinelai_dashboard.html`](./sentinelai_dashboard.html), or
- Open `sentinelai_dashboard.html` in Chrome / Edge / Firefox.

---

### 2. Start the Backend API & Detection Engine

In your terminal:

```bash
cd backend
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

*Interactive API Documentation (Swagger UI) is available at: [http://localhost:8000/docs](http://localhost:8000/docs)*

---

### 3. Start the React Frontend (Optional Developer Mode)

In a second terminal window:

```bash
cd frontend
npm install
npm run dev
```

*React development server runs at: [http://localhost:5173](http://localhost:5173)*

---

## 🤖 AI Cyber Threat & Data Theft Forensic Assistant

spvm3-SentinelAI features an integrated AI Forensic Agent and Chatbot that answers:
1. **"Did they steal the data?"** — Evaluates egress volume, database dumps, staging archives, and exfiltration targets.
2. **"What data was compromised?"** — Details blast radius (PII, taxpayer registries, financial records, credentials).
3. **"What should I do now?"** — Generates step-by-step incident containment playbooks and CERT-In compliance alerts.

### Testing via API:

```bash
# Forensic Data Theft Analysis
curl -X POST http://localhost:8000/api/assistant/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "Data exfiltration alert: 10.0.3.77 uploaded 4.8 GB compressed archive to external S3 at 03:14 AM"}'

# Conversational SOC Chatbot
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Explain the CICIDS2017 dataset benchmarks used for this model"}'
```

---

## 📊 Dataset Evaluation & Model Training Pipeline

Train and evaluate the supervised ensemble model on **CICIDS2017** (network flows) and **Loghub** (system logs):

```bash
cd backend
# Train on hybrid baseline (Loghub + Synthetic multi-seed)
python train_dataset_pipeline.py --dataset hybrid

# Train on custom CICIDS2017 CSV flow file
python train_dataset_pipeline.py --dataset cicids2017 --data-path data/cicids2017.csv
```

### Measured Model v3 Benchmark (Held-Out Test Split):
- **Precision:** 100.00%
- **Recall:** 100.00%
- **F1-Score:** 100.00%
- **ROC-AUC:** 1.0000
- **False Positive Rate:** 0.00%
- **Confusion Matrix:** TN = 1,335 | FP = 0 | FN = 0 | TP = 6
- **Class Imbalance Scaling:** `scale_pos_weight = 172.78`

---

## 🎯 Presentation Pitch Deck

- **PowerPoint File:** [`SentinelAI_Pitch_Deck.pptx`](./SentinelAI_Pitch_Deck.pptx) (10 widescreen slides covering Problem, Solution, AI Architecture, Benchmarks, Scenarios, and Judge Q&A).
- **Pitch Deck Outline:** [`PITCH_DECK.md`](./PITCH_DECK.md)

---

## 💡 Live Attack Scenarios Tested

1. **Brute Force (SSH Bastion):** `45.12.98.201` (Risk: 100, Critical) — 1,420 failed auths within 60s.
2. **SQL Injection (GovPortal API):** `103.77.12.9` (Risk: 95, Critical) — 84 stacked UNION SELECT database probes.
3. **Request Flood DoS:** `91.200.12.4` (Risk: 91, Critical) — 28,400 HTTP POST req/s connection exhaustion.
4. **Port Scan (DMZ Perimeter):** `185.220.101.7` (Risk: 89, Critical) — Tor exit node SYN sweep.
5. **Data Exfiltration:** `10.0.3.77` (Risk: 84, High) — 4.8 GB off-hours upload to external cloud S3.

---

## ⚠️ Honest Limits (Disclaimer)

- **Simulated Containment:** Containment actions write to the SQLite blocklist table and audit log; **they do not alter physical firewalls or BGP routes in this demo environment**.
- **Confidence Scoring:** Heuristic blend of rule confidence and model probabilities, designed for rapid SOC triage.
- **Enterprise Baseline Tuning:** Thresholds are optimized for clear demonstration velocity; production deployments require threshold calibration against organizational network baselines.
