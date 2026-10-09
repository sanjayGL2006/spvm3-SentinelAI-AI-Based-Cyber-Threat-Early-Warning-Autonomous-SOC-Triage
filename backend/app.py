import asyncio
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from db import init_db, get_conn
from detector import analyze
from generate_logs import generate
from ingest import ingest_batch, subscribe, unsubscribe, broadcast, ensure_dedup_index

app = FastAPI(title="spvm3-SentinelAI - Cyber Threat Early Warning")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type"])
init_db()
ensure_dedup_index()        # Phase 7: deduplication unique index
STATUSES = {"New", "Investigating", "Contained", "Resolved", "False Positive"}
REQUIRED = {"ts", "source", "src_ip"}

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _alert(r):
    d = dict(r)
    for k in ("mitre", "reasons", "actions"):
        d[k] = json.loads(d[k])
    return d

@app.post("/api/demo/generate")
def demo():
    n = generate()
    return {"events": n, "alerts": analyze()}

@app.post("/api/analyze")
def run():
    return {"alerts": analyze()}

@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "CSV files only")
    raw = await file.read()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 20 MB)")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
    if not REQUIRED.issubset(reader.fieldnames or []):
        raise HTTPException(400, f"CSV must contain columns: {sorted(REQUIRED)}")
    rows = []
    for r in reader:
        try:
            datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
            rows.append((r["ts"], r.get("source") or "network", r["src_ip"][:45], r.get("dst_ip"),
                         int(r["dst_port"]) if r.get("dst_port") else None, r.get("username"),
                         r.get("action"), r.get("status"), int(r.get("bytes_out") or 0), r.get("url"), r.get("message")))
        except (ValueError, KeyError):
            continue  # skip malformed rows
    with get_conn() as c:
        c.execute("DELETE FROM events")
        c.executemany("""INSERT OR IGNORE INTO events(ts,source,src_ip,dst_ip,dst_port,username,action,status,
                      bytes_out,url,message) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", rows)
    return {"events": len(rows), "alerts": analyze()}

@app.get("/api/alerts")
def alerts(severity: str | None = None):
    q, args = "SELECT * FROM alerts", []
    if severity:
        q += " WHERE severity=?"
        args.append(severity)
    with get_conn() as c:
        return [_alert(r) for r in c.execute(q + " ORDER BY risk DESC", args)]

@app.get("/api/stats")
def stats():
    with get_conn() as c:
        by_sev = {r["severity"]: r["n"] for r in c.execute("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
        by_threat = {r["threat"]: r["n"] for r in c.execute("SELECT threat, COUNT(*) n FROM alerts GROUP BY threat")}
        top = [dict(r) for r in c.execute("SELECT src_ip, MAX(risk) risk, COUNT(*) alerts FROM alerts GROUP BY src_ip ORDER BY risk DESC LIMIT 5")]
        ev = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = c.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
    return {"events": ev, "by_severity": by_sev, "by_threat": by_threat, "top_sources": top, "blocked_ips": blocked}

class StatusIn(BaseModel):
    status: str

@app.patch("/api/alerts/{aid}/status")
def set_status(aid: int, body: StatusIn):
    if body.status not in STATUSES:
        raise HTTPException(400, "Invalid status")
    with get_conn() as c:
        if not c.execute("UPDATE alerts SET status=? WHERE id=?", (body.status, aid)).rowcount:
            raise HTTPException(404, "Alert not found")
        c.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES (?,?,?,?)",
                  (now(), "analyst", "status_change", f"alert {aid} -> {body.status}"))
    return {"ok": True}

@app.post("/api/alerts/{aid}/respond")
def respond(aid: int):
    """SIMULATED containment: records the block + audit entry. No real firewall is touched."""
    with get_conn() as c:
        a = c.execute("SELECT src_ip FROM alerts WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Alert not found")
        c.execute("INSERT OR REPLACE INTO blocklist VALUES (?,?,?)", (a["src_ip"], now(), aid))
        c.execute("UPDATE alerts SET status='Contained' WHERE id=?", (aid,))
        c.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES (?,?,?,?)",
                  (now(), "analyst", "simulated_block", f"blocked {a['src_ip']} for alert {aid}"))
    return {"blocked": a["src_ip"], "simulated": True}

@app.get("/api/audit")
def audit():
    with get_conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50")]


# ── Phase 7: Real-time ingestion ─────────────────────────────────────────────

class IngestIn(BaseModel):
    events: list[dict[str, Any]]


@app.post("/api/ingest")
async def ingest(body: IngestIn):
    """
    Batch ingest endpoint.
    Accepts up to 5 000 events per request.
    Validates required fields, coerces types, deduplicates, and stores.
    Out-of-order timestamps are accepted (stored by real ts).
    After insertion a rolling-window analysis is triggered and an SSE
    alert-count update is broadcast to all connected clients.
    """
    if len(body.events) > 5_000:
        raise HTTPException(400, "Batch too large (max 5 000 events per request)")
    if not body.events:
        raise HTTPException(400, "events list is empty")

    result = ingest_batch(body.events)

    # Re-run detection and push an update to SSE clients.
    if result["inserted"] > 0:
        alert_count = analyze()
        asyncio.create_task(broadcast({
            "alert_count": alert_count,
            "new_events": result["inserted"],
        }))

    return result


@app.get("/api/stream")
async def stream(request: Request):
    """
    Server-Sent Events endpoint.
    Clients receive a JSON payload on every ingest that produces new alerts.
    Event format:  event: alerts\ndata: {"alert_count": N, "new_events": M}\n\n
    Clients should use EventSource (browser) or an SSE library which handles
    automatic reconnection.
    """
    q = subscribe()

    async def event_generator():
        try:
            # Send an immediate heartbeat so the browser knows the connection is live.
            yield "event: heartbeat\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"event: alerts\ndata: {json.dumps(payload)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive comment so proxies don't kill the connection.
                    yield ": keep-alive\n\n"
        finally:
            unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


# -- Phase 20: Model performance info ----------------------------------------

@app.get("/api/model_info")
def model_info():
    """
    Return the active XGBoost model's version, training metrics, and
    feature importances.  Returns 404 if no model has been trained yet.
    """
    try:
        from train_model import load_current_model, FEATURES as MODEL_FEATURES
        payload = load_current_model()
    except Exception as exc:
        raise HTTPException(500, f"Could not load model module: {exc}")

    if payload is None:
        raise HTTPException(404, "No trained model found. Run: python train_model.py")

    clf = payload["classifier"]
    metrics = payload["metrics"]

    # Feature importances
    importances = {}
    if hasattr(clf, "feature_importances_"):
        importances = {
            feat: round(float(imp), 4)
            for feat, imp in zip(MODEL_FEATURES, clf.feature_importances_)
        }

    cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]
    tp = cm[1][1]
    fpr = round(fp / (tn + fp), 4) if (tn + fp) > 0 else 0.0

    return {
        "version":       payload["version"],
        "trained_at":    payload["trained_at"],
        "data_source":   "synthetic (labelled windows from log generator)",
        "note":          (
            "Metrics are from a held-out time-based test split on synthetic data. "
            "Confidence scores are heuristic blends, not calibrated probabilities. "
            "Validate on CICIDS2017 or real logs before claiming production accuracy."
        ),
        "train_windows": metrics.get("train_windows"),
        "test_windows":  metrics.get("test_windows"),
        "precision":     metrics.get("precision"),
        "recall":        metrics.get("recall"),
        "f1":            metrics.get("f1"),
        "roc_auc":       metrics.get("roc_auc"),
        "false_pos_rate":fpr,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "feature_importances": importances,
    }


# -- AI Forensic Assistant Endpoint ------------------------------------------

class AssistantIn(BaseModel):
    query: str
    alert_id: int | None = None

@app.post("/api/assistant/analyze")
def assistant_analyze(body: AssistantIn):
    """
    Forensic AI evaluation: analyzes cyber fraud, incident data, and answers
    the question: 'Did they steal the data?'.
    """
    alert_data = None
    if body.alert_id:
        with get_conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE id=?", (body.alert_id,)).fetchone()
            if r:
                alert_data = _alert(r)
    try:
        from assistant import analyze_cyber_incident
        return analyze_cyber_incident(body.query, alert_data)
    except Exception as exc:
        raise HTTPException(500, f"Assistant analysis error: {exc}")


class ChatIn(BaseModel):
    message: str
    history: list[dict[str, str]] | None = None
    context: dict[str, Any] | None = None

@app.post("/api/chat")
def chat_endpoint(body: ChatIn):
    """
    Conversational AI Chatbot endpoint for SOC analysts.
    Answers threat inquiries, dataset details (CICIDS2017, Loghub),
    and whether data was stolen.
    """
    try:
        from assistant import chat_cyber_assistant
        return chat_cyber_assistant(body.message, body.history, body.context)
    except Exception as exc:
        raise HTTPException(500, f"Chat assistant error: {exc}")


# -- PDF Report Generation Endpoint ------------------------------------------

def _generate_minimal_pdf(title: str = "spvm3-SentinelAI Cyber Threat Forensic Report", content: str = "") -> bytes:
    stream_content = f"BT /F1 16 Tf 50 750 Td ({title}) Tj ET\nBT /F1 10 Tf 50 720 Td ({content[:100]}) Tj ET"
    stream_len = len(stream_content)
    header = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
    )
    body = f"4 0 obj << /Length {stream_len} >> stream\n{stream_content}\nendstream\nendobj\n".encode("latin1")
    footer = (
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000244 00000 n \n0000000350 00000 n \n"
        b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n440\n%%EOF\n"
    )
    return header + body + footer

@app.get("/api/reports/pdf")
@app.get("/api/alerts/{aid}/pdf")
def export_pdf_report(aid: int | None = None):
    """Generate and return an incident disclosure report as application/pdf."""
    detail = "Automated SOC Forensic Summary & Incident Audit Log"
    if aid is not None:
        detail = f"Forensic Alert Report for Incident #{aid}"
    pdf_bytes = _generate_minimal_pdf(
        title="spvm3-SentinelAI Cyber Threat Forensic Report",
        content=detail
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinelai_incident_report.pdf"}
    )



