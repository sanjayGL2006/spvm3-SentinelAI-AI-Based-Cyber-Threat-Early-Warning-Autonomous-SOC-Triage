"""Hybrid detector: feature windows -> rules (explainable) + IsolationForest (unknown patterns)
+ XGBoost supervised classifier (Phase 20) -> risk score 0-100 -> severity -> MITRE ATT&CK.

Ensemble weights (when XGBoost model is present):
  risk = (0.75 * rule_score + 20 * anomaly_score + 15 * xgb_prob) * criticality_scaler
When no model file exists the system falls back to the original weights seamlessly.
"""
import json
import re
import logging
from collections import defaultdict
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import IsolationForest
from db import get_conn

logger = logging.getLogger(__name__)

# ── Phase 20: XGBoost ensemble component ─────────────────────────────────────
_xgb_cache: dict = {}   # {"model": clf | None, "version": int | None}

def _load_xgb():
    """
    Lazy-load the current XGBoost model from models/.
    Returns the classifier object, or None if not trained yet.
    Re-loads automatically when the version file changes.
    """
    try:
        from train_model import load_current_model, CURRENT_PTR
        if not CURRENT_PTR.exists():
            return None
        v = int(CURRENT_PTR.read_text().strip())
        if _xgb_cache.get("version") != v:
            payload = load_current_model()
            _xgb_cache["model"]   = payload["classifier"] if payload else None
            _xgb_cache["version"] = v
            if payload:
                logger.info("XGBoost model v%s loaded into detector", v)
        return _xgb_cache.get("model")
    except Exception as exc:
        logger.warning("Could not load XGBoost model: %s", exc)
        return None

WINDOW_MIN = 5
SQLI_RE = re.compile(r"(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|--|;\s*drop\s|<script)", re.I)
ASSET_CRITICALITY = {"10.0.9.10": 1.0,   # HR / auth portal
                     "10.0.9.20": 0.8,   # citizen web portal
                     "10.0.9.30": 0.5}   # internal network services
FEATURES = ["events", "failed_logins", "distinct_ports", "bytes_out", "web_requests",
            "error_ratio", "sqli_hits", "off_hours"]

ACTIONS = {
    "Brute Force": ["Block source IP at firewall", "Force password reset + enable MFA", "Review successful logins after failures"],
    "Port Scan": ["Block source IP", "Review exposed services", "Enable IDS signature for scanning"],
    "SQL Injection": ["Block source IP / enable WAF rule", "Audit database queries on affected URL", "Patch input validation"],
    "Data Exfiltration": ["Isolate host from network", "Preserve logs for forensics", "Notify CISO / data-protection officer"],
    "Request Flood (DoS)": ["Rate-limit / block source", "Enable upstream DDoS protection", "Scale or fail over the service"],
    "Anomalous Behaviour": ["Investigate manually", "Compare with the user/host baseline"],
}
MITRE = {
    "Brute Force": ["T1110 Brute Force", "T1078 Valid Accounts"],
    "Port Scan": ["T1046 Network Service Discovery"],
    "SQL Injection": ["T1190 Exploit Public-Facing Application"],
    "Data Exfiltration": ["T1041 Exfiltration Over C2 Channel"],
    "Request Flood (DoS)": ["T1498 Network Denial of Service"],
    "Anomalous Behaviour": ["TA0043 Reconnaissance (unclassified)"],
}

def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def build_windows(rows):
    buckets = defaultdict(list)
    for r in rows:
        t = _parse(r["ts"])
        key = (r["src_ip"], t.replace(minute=t.minute - t.minute % WINDOW_MIN, second=0, microsecond=0))
        buckets[key].append(r)
    out = []
    for (ip, start), evs in buckets.items():
        failed = [e for e in evs if e["source"] == "auth" and e["status"] == "failed"]
        succ = [e for e in evs if e["source"] == "auth" and e["status"] == "success"]
        web = [e for e in evs if e["source"] == "web"]
        errs = [e for e in web if str(e["status"]).startswith(("4", "5"))]
        last_fail = max((e["ts"] for e in failed), default=None)
        out.append({
            "src_ip": ip, "window_start": start.isoformat(),
            "target": max(set(e["dst_ip"] for e in evs if e["dst_ip"]), key=lambda x: sum(1 for e in evs if e["dst_ip"] == x), default=None),
            "events": len(evs), "failed_logins": len(failed),
            "success_after_fail": bool(failed and any(s["ts"] > last_fail for s in succ)),
            "distinct_ports": len({e["dst_port"] for e in evs if e["source"] == "network" and e["dst_port"]}),
            "bytes_out": sum(e["bytes_out"] or 0 for e in evs),
            "web_requests": len(web),
            "error_ratio": (len(errs) / len(web)) if web else 0.0,
            "sqli_hits": sum(1 for e in web if e["url"] and SQLI_RE.search(e["url"])),
            "off_hours": 1 if (start.hour < 6 or start.hour >= 22) else 0,
        })
    return out

def apply_rules(w):
    """Return (threat, rule_score 0-100, reasons) or None. Each reason is human-readable XAI output."""
    if w["sqli_hits"] >= 3:
        return "SQL Injection", 75 + min(w["sqli_hits"], 15), [
            f"{w['sqli_hits']} requests with SQL/script injection patterns in the URL",
            f"Error ratio on web requests: {w['error_ratio']:.0%}"]
    if w["failed_logins"] >= 10:
        r = [f"{w['failed_logins']} failed logins from one IP in {WINDOW_MIN} minutes"]
        s = 60 + min(w["failed_logins"], 20)
        if w["success_after_fail"]:
            s += 20
            r.append("Successful login immediately after repeated failures (possible account takeover)")
        return "Brute Force", s, r
    if w["distinct_ports"] >= 30:
        return "Port Scan", 65 + min(w["distinct_ports"] // 5, 25), [
            f"{w['distinct_ports']} distinct destination ports probed in {WINDOW_MIN} minutes"]
    if w["bytes_out"] >= 500_000_000:
        r = [f"{w['bytes_out'] / 1e6:,.0f} MB sent to an external address"]
        s = 70
        if w["off_hours"]:
            s += 15
            r.append("Transfer happened during off-hours (22:00-06:00 UTC)")
        return "Data Exfiltration", s, r
    if w["web_requests"] >= 300:
        return "Request Flood (DoS)", 70 + min(w["web_requests"] // 50, 20), [
            f"{w['web_requests']} web requests from a single IP in {WINDOW_MIN} minutes"]
    return None

def severity(risk: int) -> str:
    return "Critical" if risk >= 85 else "High" if risk >= 70 else "Medium" if risk >= 45 else "Low"

def analyze():
    with get_conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM events ORDER BY ts")]
    if not rows:
        return 0
    windows = build_windows(rows)
    X = np.array([[float(w[f]) for f in FEATURES] for w in windows])

    # IsolationForest anomaly scores
    if len(windows) >= 20:
        iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
        raw = -iso.score_samples(X)
        anomaly = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    else:
        anomaly = np.zeros(len(windows))
    mean, std = X.mean(0), X.std(0) + 1e-9
    z = (X - mean) / std

    # Phase 20: XGBoost probabilities (None when model not yet trained)
    xgb_clf = _load_xgb()
    if xgb_clf is not None:
        try:
            xgb_probs = xgb_clf.predict_proba(X)[:, 1]   # P(attack)
        except Exception as exc:
            logger.warning("XGBoost predict failed: %s", exc)
            xgb_probs = None
    else:
        xgb_probs = None

    alerts = []
    for i, (w, a, zrow) in enumerate(zip(windows, anomaly, z)):
        xp = float(xgb_probs[i]) if xgb_probs is not None else None

        rule = apply_rules(w)
        if rule:
            threat, rscore, reasons = rule
        elif (xp is not None and xp >= 0.70) or (xp is None and a >= 0.85) or (a >= 0.85 and xp is not None and xp >= 0.30):
            # Anomalous by IsolationForest OR flagged by XGBoost
            top = FEATURES[int(np.argmax(zrow))]
            threat, rscore, reasons = "Anomalous Behaviour", 50, [
                f"Isolation Forest flagged this window as an outlier (score {a:.2f})",
                f"Most unusual signal: {top} = {w[top]:.2f} (z-score {zrow.max():.1f})"]
        else:
            continue

        crit = ASSET_CRITICALITY.get(w["target"], 0.5)

        # ── Ensemble risk score ───────────────────────────────────────────
        if xp is not None:
            # Three-component ensemble: rules (75%) + IsoForest (20%) + XGB (15%)
            # Weights purposely favour rules for explainability.
            raw_risk = (0.75 * rscore + 20 * a * 100 / 100 + 15 * xp * 100 / 100)
            if xp >= 0.60:
                reasons.append(
                    f"XGBoost classifier: {xp*100:.0f}% probability of attack "
                    f"(trained on labelled synthetic windows; heuristic, not calibrated)")
        else:
            # Original two-component formula (no model loaded)
            raw_risk = 0.75 * rscore + 25 * a * 100 / 100

        risk = int(min(100, raw_risk * (0.85 + 0.3 * crit)))
        sev = severity(risk)
        reasons.append(f"Target asset criticality: {crit:.1f} ({w['target']})")
        actions = list(ACTIONS[threat])
        if sev in ("Critical", "High"):
            actions.append("Escalate to CISO; assess CERT-In / regulatory reporting obligation")

        confidence = round(min(0.99, 0.55 + risk / 250 + 0.2 * a + (0.1 * xp if xp else 0)), 2)
        alerts.append((datetime.now(timezone.utc).isoformat(), w["window_start"], w["src_ip"], w["target"],
                       threat, risk, sev, confidence, round(float(a), 3),
                       json.dumps(MITRE[threat]), json.dumps(reasons), json.dumps(actions)))

    with get_conn() as c:
        c.execute("DELETE FROM alerts")
        c.executemany("""INSERT INTO alerts(created_at,window_start,src_ip,target,threat,risk,severity,
                      confidence,anomaly_score,mitre,reasons,actions) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", alerts)
    return len(alerts)
