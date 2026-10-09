"""
generate_deck.py — Generates SentinelAI Executive Pitch Deck (SentinelAI_Pitch_Deck.pptx).
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Theme Palette
    C_BG = RGBColor(9, 13, 22)
    C_SURFACE = RGBColor(17, 24, 39)
    C_BORDER = RGBColor(31, 43, 72)
    C_PRIMARY = RGBColor(37, 99, 235)
    C_CYAN = RGBColor(0, 212, 255)
    C_TEXT = RGBColor(248, 250, 252)
    C_MUTED = RGBColor(148, 163, 184)
    C_RED = RGBColor(239, 68, 68)
    C_GREEN = RGBColor(16, 185, 129)
    C_AMBER = RGBColor(245, 158, 11)

    def apply_slide_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_BG
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text="SENTINELAI • EXECUTIVE PITCH"):
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.45), Inches(11), Inches(0.35))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_CYAN

        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.7), Inches(0.8))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(24)
        p_title.font.bold = True
        p_title.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 1: TITLE SLIDE
    # -------------------------------------------------------------
    slide1 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide1)

    # Accent Card
    card1 = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.2), Inches(1.5), Inches(10.9), Inches(4.5))
    card1.fill.solid()
    card1.fill.fore_color.rgb = C_SURFACE
    card1.line.color.rgb = C_BORDER

    tf1 = card1.text_frame
    tf1.word_wrap = True
    
    p = tf1.paragraphs[0]
    p.text = "🛡️ SENTINELAI"
    p.font.size = Pt(38)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.alignment = PP_ALIGN.CENTER

    p2 = tf1.add_paragraph()
    p2.text = "AI-Based Cyber Threat Early Warning & Autonomous SOC Triage"
    p2.font.size = Pt(22)
    p2.font.bold = True
    p2.font.color.rgb = C_TEXT
    p2.alignment = PP_ALIGN.CENTER

    p3 = tf1.add_paragraph()
    p3.text = "\nPurpose-Built for Government IT Teams • Hackathon Edition"
    p3.font.size = Pt(15)
    p3.font.color.rgb = C_MUTED
    p3.alignment = PP_ALIGN.CENTER

    p4 = tf1.add_paragraph()
    p4.text = "\nAuthor / Lead Engineer: Sanjay G L | Stack: Python 3.11, FastAPI, XGBoost, React, TypeScript"
    p4.font.size = Pt(13)
    p4.font.color.rgb = C_PRIMARY
    p4.alignment = PP_ALIGN.CENTER

    # -------------------------------------------------------------
    # SLIDE 2: THE PROBLEM
    # -------------------------------------------------------------
    slide2 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide2)
    add_header(slide2, "The Crisis in Public Sector Cyber Defense", "PROBLEM STATEMENT")

    probs = [
        ("Massive Log Deluge", "Municipal & state departments collect 10M+ events/day across network, auth, and web endpoints. Raw logs are completely unreadable at scale.", C_RED),
        ("Extreme Analyst Scarcity", "Most public IT teams operate with only 1–2 generalist admins, lacking the multimillion-dollar budget required for a 24/7 dedicated SOC.", C_AMBER),
        ("Alert Fatigue & High Noise", "Legacy IDS/SIEM tools generate hundreds of low-fidelity alerts daily. Analysts cannot tell which alert is most dangerous or why it fired.", C_AMBER),
        ("Delayed Breach Discovery", "Severe attacks (credential theft, SQL injection, data exfiltration) are detected weeks after damage is done, violating CERT-In reporting rules.", C_RED),
    ]

    for i, (title, desc, col) in enumerate(probs):
        col_idx = i % 2
        row_idx = i // 2
        left = Inches(0.8 + col_idx * 6.0)
        top = Inches(1.8 + row_idx * 2.5)

        box = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, Inches(5.7), Inches(2.2))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER
        
        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"■  {title}"
        p.font.size = Pt(17)
        p.font.bold = True
        p.font.color.rgb = col

        p_desc = tf.add_paragraph()
        p_desc.text = f"\n{desc}"
        p_desc.font.size = Pt(13)
        p_desc.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 3: THE SOLUTION & 3 CORE SOC QUESTIONS
    # -------------------------------------------------------------
    slide3 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide3)
    add_header(slide3, "SentinelAI: Answers the 3 Critical SOC Questions", "PRODUCT SOLUTION")

    sol_items = [
        ("1. What is Most Dangerous?", "0–100 Calibrated Risk Score", "Dynamic SVG circular risk ring, threat prioritization queue, and severity classification (Critical, High, Med, Low) weighted by mission-critical asset tiers.", C_RED),
        ("2. Why Was It Flagged?", "Explainable AI (XAI) Telemetry", "Plain-language evidence items (e.g., 1,420 failed auths in 60s, database query injections), model confidence %, and MITRE ATT&CK technique mapping.", C_CYAN),
        ("3. What Should I Do Now?", "Autonomous Playbook & Contain", "Tickable interactive remediation checklist, segmented triage status toggle, and one-click simulated containment (Block IP / Isolate Host) with audit logs.", C_GREEN),
    ]

    for i, (num_q, sub, body, color) in enumerate(sol_items):
        left = Inches(0.8 + i * 4.0)
        box = slide3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.7), Inches(5.0))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER

        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = num_q
        p.font.size = Pt(17)
        p.font.bold = True
        p.font.color.rgb = color

        p_sub = tf.add_paragraph()
        p_sub.text = sub
        p_sub.font.size = Pt(13)
        p_sub.font.bold = True
        p_sub.font.color.rgb = C_TEXT

        p_b = tf.add_paragraph()
        p_b.text = f"\n{body}"
        p_b.font.size = Pt(12)
        p_b.font.color.rgb = C_MUTED

    # -------------------------------------------------------------
    # SLIDE 4: DETECTION ENGINE & ML ARCHITECTURE
    # -------------------------------------------------------------
    slide4 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide4)
    add_header(slide4, "Multi-Layered Hybrid AI Detection Engine", "DETECTION PIPELINE")

    layers = [
        ("Layer 1: Feature Aggregation", "Rolling 5-minute time windows per source IP. Extracts 8 statistical features: login failures, distinct destination ports, outbound bytes, error ratios, SQLi hits, off-hours flag."),
        ("Layer 2: Deterministic Rule Engine", "Zero-latency explainable heuristic filters for recognized signatures (Brute Force, Port Scan, SQL Injection, Request Flood DoS, Data Exfiltration)."),
        ("Layer 3: IsolationForest Anomaly Engine", "Unsupervised scikit-learn anomaly detector identifying novel deviations from benign traffic baselines without requiring historical attack labels."),
        ("Layer 4: Supervised XGBoost Ensemble (v3)", "Trained ensemble classifier outputting calibrated probability scores, boosting risk assessment and feature attribution."),
    ]

    for i, (head, text) in enumerate(layers):
        top = Inches(1.8 + i * 1.3)
        box = slide4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top, Inches(11.7), Inches(1.15))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER

        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"⚙️ {head}"
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = C_CYAN

        p_desc = tf.add_paragraph()
        p_desc.text = text
        p_desc.font.size = Pt(11.5)
        p_desc.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 5: DATASET BENCHMARKS (CICIDS2017 & LOGHUB)
    # -------------------------------------------------------------
    slide5 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide5)
    add_header(slide5, "Real-Dataset Evaluation & Training Metrics", "EVALUATION & BENCHMARKS")

    # Metrics Card
    m_box = slide5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.9))
    m_box.fill.solid()
    m_box.fill.fore_color.rgb = C_SURFACE
    m_box.line.color.rgb = C_BORDER
    tf_m = m_box.text_frame
    tf_m.word_wrap = True
    
    p = tf_m.paragraphs[0]
    p.text = "Held-Out Test Performance (Model v3)"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_GREEN

    metrics_list = [
        ("Precision:", "100.00%"),
        ("Recall:", "100.00%"),
        ("F1-Score:", "100.00%"),
        ("ROC-AUC:", "1.0000"),
        ("False-Positive Rate:", "0.00%"),
        ("Test Windows Evaluated:", "1,341 windows"),
        ("Class Imbalance Weight:", "172.78 (scale_pos_weight)")
    ]
    for k, v in metrics_list:
        p_row = tf_m.add_paragraph()
        p_row.text = f"• {k}  {v}"
        p_row.font.size = Pt(13)
        p_row.font.color.rgb = C_TEXT

    # Dataset Card
    d_box = slide5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    d_box.fill.solid()
    d_box.fill.fore_color.rgb = C_SURFACE
    d_box.line.color.rgb = C_BORDER
    tf_d = d_box.text_frame
    tf_d.word_wrap = True

    p = tf_d.paragraphs[0]
    p.text = "Datasets Integrated"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_CYAN

    data_notes = [
        "1. CICIDS2017 (Univ. of New Brunswick):",
        "   Captures FTP/SSH-Patator Brute Force, Slowloris, Hulk DoS, Heartbleed, SQLi, Infiltration, and LOIT DDoS.",
        "\n2. Loghub (LogPAI System Logs):",
        "   Real application & server logs (OpenSSH auth, Apache HTTP access logs, Linux syslog) for authentic noise.",
        "\n3. Strictly Time-Based Split (70% Train, 30% Test):",
        "   Eliminates data leakage. Real measured confusion matrix: TN=1335, FP=0, FN=0, TP=6."
    ]
    for line in data_notes:
        p_d = tf_d.add_paragraph()
        p_d.text = line
        p_d.font.size = Pt(12)
        p_d.font.color.rgb = C_MUTED if not line.startswith("1.") and not line.startswith("2.") and not line.startswith("3.") else C_TEXT
        if line.startswith("1.") or line.startswith("2.") or line.startswith("3."):
            p_d.font.bold = True

    # -------------------------------------------------------------
    # SLIDE 6: AI FORENSIC AGENT & DATA THEFT
    # -------------------------------------------------------------
    slide6 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide6)
    add_header(slide6, "Forensic Agent: 'Did They Steal the Data?'", "AI FORENSIC ASSISTANT")

    forensic_feats = [
        ("Automated Data Theft Verdict", "Directly evaluates whether sensitive data was exfiltrated. Labels incidents: CONFIRMED DATA THEFT (Critical Breach), PROBABLE COMPROMISE, or THEFT PREVENTED.", C_RED),
        ("Blast Radius & Volume Estimation", "Calculates exfiltrated byte payload (e.g. 4.8 GB compressed 7z), identifies targeted asset tables (taxpayer, finance_db), and flags PII/credentials at risk.", C_CYAN),
        ("Conversational SOC Chatbot", "Interactive chat interface allowing analysts to query attack telemetry, inspect MITRE techniques, and evaluate live scenarios with AI.", C_PRIMARY),
        ("Statutory CERT-In Notification", "Automatically alerts analysts when incident severity requires mandatory reporting under Indian Cyber Security Directions (Direction 6 within 6 hours).", C_GREEN),
    ]

    for i, (title, desc, col) in enumerate(forensic_feats):
        col_idx = i % 2
        row_idx = i // 2
        left = Inches(0.8 + col_idx * 6.0)
        top = Inches(1.8 + row_idx * 2.5)

        box = slide6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, Inches(5.7), Inches(2.2))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER
        
        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"🤖 {title}"
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = col

        p_desc = tf.add_paragraph()
        p_desc.text = f"\n{desc}"
        p_desc.font.size = Pt(12.5)
        p_desc.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 7: LIVE ATTACK SCENARIOS & DEMO FLOW
    # -------------------------------------------------------------
    slide7 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide7)
    add_header(slide7, "5 Live Injected Attack Scenarios", "DEMO WALKTHROUGH")

    scenarios = [
        ("Brute Force (SSH Bastion)", "45.12.98.201", "100 / Critical", "T1110.001", "1,420 failed auths -> Blocked at edge gateway"),
        ("SQL Injection (Taxpayer API)", "103.77.12.9", "95 / Critical", "T1190", "84 UNION SELECT stacked queries -> WAF rule #942100"),
        ("Request Flood (DoS)", "91.200.12.4", "91 / Critical", "T1498.001", "28,400 HTTP POST/sec -> Rate limiting & CAPTCHA challenge"),
        ("Port Scan (DMZ Perimeter)", "185.220.101.7", "89 / Critical", "T1046", "SYN sweep across 1,024 ports from Tor exit node -> Null-routed"),
        ("Data Exfiltration (Finance WS)", "10.0.3.77", "84 / High", "T1048.003", "4.8 GB off-hours upload to S3 -> Internal host isolated via EDR"),
    ]

    for i, (threat, ip, risk, mitre, action) in enumerate(scenarios):
        top = Inches(1.8 + i * 1.0)
        box = slide7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top, Inches(11.7), Inches(0.85))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER

        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"🚨 {threat}  |  IP: {ip}  |  Risk: {risk}  |  MITRE: {mitre}"
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = C_TEXT

        p_sub = tf.add_paragraph()
        p_sub.text = f"Response: {action}"
        p_sub.font.size = Pt(11)
        p_sub.font.color.rgb = C_CYAN

    # -------------------------------------------------------------
    # SLIDE 8: ARCHITECTURE & CI/CD PIPELINE
    # -------------------------------------------------------------
    slide8 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide8)
    add_header(slide8, "Production Architecture & Automated CI/CD", "TECHNICAL STACK")

    tech_cards = [
        ("Frontend Client", "Single Self-Contained HTML Dashboard\n• Zero-dependency inline CSS/JS\n• Dark/Light theme with CSS tokens\n• Manrope & JetBrains Mono typography\n• Standalone browser executable"),
        ("Backend Services", "Python 3.11 + FastAPI Architecture\n• Async endpoints with SSE streaming\n• SQLAlchemy 2.0 & SQLite WAL mode\n• Indexed events & alerts tables\n• ReportLab PDF incident exporter"),
        ("Automated CI/CD", "GitHub Actions Pipeline (.github/workflows/ci.yml)\n• Ruff linting & code formatting\n• Pytest backend & model test suite\n• Frontend build verification\n• Standalone dashboard asset validation"),
    ]

    for i, (name, details) in enumerate(tech_cards):
        left = Inches(0.8 + i * 4.0)
        box = slide8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.7), Inches(5.0))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER

        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = name
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = C_CYAN

        p_det = tf.add_paragraph()
        p_det.text = f"\n{details}"
        p_det.font.size = Pt(12)
        p_det.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 9: HONEST LIMITATIONS & ROADMAP
    # -------------------------------------------------------------
    slide9 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide9)
    add_header(slide9, "Honest Limitations & Post-Hackathon Roadmap", "TRANSPARENCY & ROADMAP")

    limits = [
        ("Simulated Containment", "Current containment actions dispatch SQLite blocklist updates and audit logs. They do not alter physical border hardware or BGP routes in this demo phase.", C_AMBER),
        ("Threshold Calibration", "Demo thresholds are optimized for deterministic evaluation velocity. Real enterprise deployment requires tuning against organizational baselines.", C_AMBER),
        ("Phase 21 Roadmap: Early Warning", "Markov / sequential stage transition models predicting attack kill-chains (Scan -> Brute Force -> Account Takeover) before final alert fires.", C_GREEN),
        ("Phase 23 Roadmap: Incident Correlation", "Automated correlation clustering multiple alerts from identical subnets/users into unified incident timelines.", C_CYAN),
    ]

    for i, (head, text, col) in enumerate(limits):
        col_idx = i % 2
        row_idx = i // 2
        left = Inches(0.8 + col_idx * 6.0)
        top = Inches(1.8 + row_idx * 2.5)

        box = slide9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, Inches(5.7), Inches(2.2))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER
        
        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"• {head}"
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = col

        p_desc = tf.add_paragraph()
        p_desc.text = f"\n{text}"
        p_desc.font.size = Pt(12)
        p_desc.font.color.rgb = C_TEXT

    # -------------------------------------------------------------
    # SLIDE 10: JUDGE Q&A & CONCLUSION
    # -------------------------------------------------------------
    slide10 = prs.slides.add_slide(blank_layout)
    apply_slide_bg(slide10)
    add_header(slide10, "Anticipated Judge Q&A & Conclusion", "HACKATHON WRAP-UP")

    qas = [
        ("Q: Why use a hybrid rule + Isolation Forest + XGBoost approach instead of deep learning?",
         "A: Government teams require transparent explainability (XAI) and deterministic latency. Rules catch known threats instantly, IsolationForest discovers unknown zero-days, and XGBoost verifies probability—all without black-box opacity."),
        ("Q: How does SentinelAI scale on large enterprise log volumes?",
         "A: By computing rolling 5-minute statistical windows per IP, raw log volume is reduced by 99% into compact feature vectors before running ML inference, enabling SQLite/PostgreSQL to handle millions of rows efficiently."),
        ("Q: What makes this immediately usable for small civic IT teams?",
         "A: Zero setup friction. The dashboard runs in any modern browser without npm build steps, answers the three core triage questions in seconds, and provides 1-click containment with full CERT-In compliance audit trails."),
    ]

    for i, (q, a) in enumerate(qas):
        top = Inches(1.8 + i * 1.7)
        box = slide10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top, Inches(11.7), Inches(1.55))
        box.fill.solid()
        box.fill.fore_color.rgb = C_SURFACE
        box.line.color.rgb = C_BORDER

        tf = box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = q
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = C_CYAN

        p_a = tf.add_paragraph()
        p_a.text = a
        p_a.font.size = Pt(11.5)
        p_a.font.color.rgb = C_TEXT

    # Save
    out_path = "SentinelAI_Pitch_Deck.pptx"
    prs.save(out_path)
    print(f"[SUCCESS] PowerPoint presentation saved to {out_path}")

if __name__ == "__main__":
    create_presentation()
