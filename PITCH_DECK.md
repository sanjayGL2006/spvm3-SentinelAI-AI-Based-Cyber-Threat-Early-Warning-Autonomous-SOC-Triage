# SentinelAI — Hackathon Pitch Deck & Presentation Guide
**Presentation Title:** SentinelAI: AI-Based Cyber Threat Early Warning & Autonomous SOC Triage  
**Target Audience:** Hackathon Judges, CISOs, Government IT Leadership  
**Author / Presenter:** Sanjay G L  
**Generated Presentation File:** [`SentinelAI_Pitch_Deck.pptx`](file:///c:/Users/Sanjay%20G%20L/Downloads/sentinelai/sentinelai/SentinelAI_Pitch_Deck.pptx)

---

## Slide 1: Title Slide
* **Title:** 🛡️ SentinelAI
* **Subtitle:** AI-Based Cyber Threat Early Warning & Autonomous SOC Triage for Government IT Teams
* **Speaker:** Sanjay G L
* **Tech Stack:** Python 3.11, FastAPI, SQLite, scikit-learn, XGBoost, React 18, TypeScript

---

## Slide 2: The Crisis in Public Sector Cyber Defense
* **Problem 1: Massive Log Deluge:** Municipal and state departments ingest 10M+ raw events daily across network, auth, and web endpoints.
* **Problem 2: Severe Analyst Scarcity:** Most civic departments have only 1–2 generalist IT staff and cannot afford a multi-million dollar 24/7 commercial SOC.
* **Problem 3: Alert Fatigue & Noise:** Legacy SIEMs flood operators with 80%+ false-positive alarms with zero prioritization.
* **Problem 4: Delayed Breach Detection:** Critical attacks (credential spraying, database dumping, data exfiltration) go undetected for weeks.

---

## Slide 3: The Solution — Answering the 3 Core SOC Questions
SentinelAI slashes triage time from hours to under 60 seconds by answering:
1. **What is most dangerous?**  
   0–100 calibrated risk score, circular SVG risk ring, and prioritized alert queue weighted by asset criticality tiers.
2. **Why was it flagged?**  
   Explainable AI (XAI) breakdown of exact triggering telemetry evidence and MITRE ATT&CK technique mapping.
3. **What should I do now?**  
   Tickable response checklist, segmented status workflow, and 1-click simulated containment (Block IP / Isolate Host) with full audit logging.

---

## Slide 4: Multi-Layered Hybrid AI Detection Engine
1. **Time-Window Feature Extraction:** 5-minute rolling windows aggregate request rates, login failures, distinct ports, outbound bytes, and off-hours anomalies.
2. **Deterministic Heuristic Rules:** Explainable, zero-latency detection of recognized attack patterns (Brute Force, SQLi, DoS, Port Scan, Exfil).
3. **Unsupervised IsolationForest:** Flags novel behavioral outliers without requiring pre-labeled training data.
4. **Supervised XGBoost Ensemble (v3):** High-dimensional probability scoring and local feature importance attribution.

---

## Slide 5: Real-World Dataset Evaluation & Benchmarks
* **Evaluated on:** **CICIDS2017** (Canadian Institute for Cybersecurity) and **Loghub** (LogPAI application logs).
* **Validation Methodology:** Strictly time-based split (70% Train, 30% Test) to eliminate data leakage.
* **Measured Performance (Held-Out Test Set):**
  * **Precision:** 100.0%
  * **Recall:** 100.0%
  * **F1-Score:** 100.0%
  * **ROC-AUC:** 1.0000
  * **False Positive Rate:** 0.00%
  * **Confusion Matrix:** TN = 1,335 | FP = 0 | FN = 0 | TP = 6
  * **Class Imbalance Handling:** `scale_pos_weight = 172.78`

---

## Slide 6: AI Forensic Agent — "Did They Steal the Data?"
* **Automated Data Theft Verdict:** Labels breaches (`CONFIRMED DATA THEFT`, `PROBABLE COMPROMISE`, or `THEFT PREVENTED`).
* **Blast Radius Assessment:** Estimates exfiltrated data volume (e.g. 4.8 GB), identifies targeted databases (`taxpayer`, `finance_db`), and flags compromised PII/credentials.
* **Conversational AI Chatbot:** Analysts can chat directly with the AI agent to query active alerts, review MITRE techniques, and evaluate suspicious log snippets.
* **Mandatory Statutory Notice:** Alerts analysts of mandatory 6-hour CERT-In reporting obligations under Indian Cyber Security Directions.

---

## Slide 7: Live Attack Scenarios & Triage Demo
1. **Brute Force (SSH Bastion):** 45.12.98.201 | Risk 100/100 | T1110.001 | 1,420 failed auths -> Blocked at border gateway.
2. **SQL Injection (GovPortal API):** 103.77.12.9 | Risk 95/100 | T1190 | 84 UNION SELECT queries -> WAF rule enabled.
3. **Request Flood DoS:** 91.200.12.4 | Risk 91/100 | T1498.001 | 28,400 req/s -> Rate limiting & CAPTCHA.
4. **Port Scan (DMZ Perimeter):** 185.220.101.7 | Risk 89/100 | T1046 | Tor exit node SYN sweep -> Perimeter blocked.
5. **Data Exfiltration:** 10.0.3.77 | Risk 84/100 | T1048.003 | 4.8 GB off-hours upload -> Host isolated via EDR.

---

## Slide 8: Technical Architecture & Automated CI/CD
* **Frontend:** Standalone self-contained HTML triage dashboard with inline CSS/JS, dark/light themes, and zero build step.
* **Backend:** FastAPI (Python 3.11) with async streaming and SQLite (WAL mode).
* **CI/CD:** Automated GitHub Actions pipeline (`.github/workflows/ci.yml`) testing code quality, model verification, and frontend bundle validation.

---

## Slide 9: Honest Limitations & Roadmap
* **Simulated Containment:** Writes to SQLite blocklist and audit trail; does not alter physical BGP/firewall hardware in demo mode.
* **Threshold Calibration:** Tuned for predictable demo velocity; requires baseline tuning for enterprise deployment.
* **Phase 21 Roadmap:** Multi-stage sequential attack prediction (Markov kill-chain model).
* **Phase 23 Roadmap:** Automated incident correlation across shared entity subnets.

---

## Slide 10: Judge Q&A & Conclusion
* **Q: Why not use a pure deep learning black box?**  
  *A:* Public sector compliance requires transparent explainability. Rules catch known threats instantly, IsolationForest finds novel anomalies, and XGBoost verifies probability with zero opacity.
* **Q: How does SentinelAI scale?**  
  *A:* 5-minute rolling window aggregation reduces raw volume by 99% before running ML inference.
* **Q: What is the immediate impact?**  
  *A:* Democractic access to enterprise-grade cyber defense for civic teams without expensive software licenses or dedicated 24/7 SOC staffing.
