import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend directory is in python search path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import app
from db import init_db, get_conn
from detector import _load_xgb
from assistant import analyze_cyber_incident


@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch, tmp_path):
    """Use an isolated temporary SQLite database for each test."""
    test_db_path = str(tmp_path / "test_sentinel.db")
    monkeypatch.setenv("SENTINEL_DB", test_db_path)
    init_db()
    yield test_db_path


@pytest.fixture
def client():
    return TestClient(app)


def test_upload_sample_logs_csv_returns_5_alerts(client):
    """Uploading sample_logs.csv should detect 5 simulated multi-stage attacks."""
    csv_path = BACKEND_DIR / "data" / "sample_logs.csv"
    if not csv_path.exists():
        pytest.skip("sample_logs.csv not found in backend/data")
    with open(csv_path, "rb") as f:
        response = client.post("/api/upload", files={"file": ("sample_logs.csv", f, "text/csv")})
    assert response.status_code == 200
    data = response.json()
    assert data["alerts"] == 5, f"Expected 5 alerts, got {data['alerts']}"


def test_upload_sample_logs_clean_csv_returns_0_alerts(client):
    """Uploading sample_logs_clean.csv should detect 0 false positives."""
    csv_path = BACKEND_DIR / "data" / "sample_logs_clean.csv"
    if not csv_path.exists():
        pytest.skip("sample_logs_clean.csv not found in backend/data")
    with open(csv_path, "rb") as f:
        response = client.post("/api/upload", files={"file": ("sample_logs_clean.csv", f, "text/csv")})
    assert response.status_code == 200
    data = response.json()
    assert data["alerts"] == 0, f"Expected 0 alerts on clean traffic, got {data['alerts']}"


def test_upload_non_csv_returns_400(client):
    """Uploading a non-CSV file should return HTTP 400."""
    fake_content = b"Not a CSV payload"
    response = client.post("/api/upload", files={"file": ("malicious_payload.exe", fake_content, "application/octet-stream")})
    assert response.status_code == 400
    assert "CSV files only" in response.json().get("detail", "")


def test_upload_missing_columns_returns_400(client):
    """Uploading a CSV without required columns (ts, source, src_ip) should return HTTP 400."""
    invalid_csv = b"random_col_1,random_col_2\nval1,val2\n"
    response = client.post("/api/upload", files={"file": ("invalid.csv", invalid_csv, "text/csv")})
    assert response.status_code == 400
    assert "CSV must contain columns" in response.json().get("detail", "")


def test_invalid_alert_status_returns_400(client):
    """Updating alert to an invalid status should return HTTP 400."""
    # Seed an alert first
    with get_conn() as c:
        c.execute("""INSERT INTO alerts(created_at,window_start,src_ip,target,threat,risk,severity,confidence,anomaly_score,mitre,reasons,actions,status)
                     VALUES ('2026-10-09T00:00:00Z','2026-10-09T00:00:00Z','192.168.1.1','10.0.9.10','Brute Force',90,'Critical',0.9,0.8,'[]','[]','[]','New')""")
        aid = c.execute("SELECT id FROM alerts LIMIT 1").fetchone()["id"]

    response = client.patch(f"/api/alerts/{aid}/status", json={"status": "HackedStatus"})
    assert response.status_code == 400
    assert response.json().get("detail") == "Invalid status"


def test_missing_alert_returns_404(client):
    """Attempting to update status of a non-existent alert ID should return HTTP 404."""
    response = client.patch("/api/alerts/999999/status", json={"status": "Investigating"})
    assert response.status_code == 404
    assert response.json().get("detail") == "Alert not found"


def test_pdf_endpoint_returns_application_pdf(client):
    """The PDF report endpoint must return Content-Type application/pdf."""
    response = client.get("/api/reports/pdf")
    assert response.status_code == 200
    assert "application/pdf" in response.headers.get("content-type", "")
    assert response.content.startswith(b"%PDF-")


def test_model_loads_successfully():
    """Verify that the model loader successfully returns a trained classifier."""
    clf = _load_xgb()
    assert clf is not None, "Classifier model must not be None"


def test_assistant_forensic_incident_detection():
    """Verify AI forensic assistant correctly detects data theft in security text."""
    res = analyze_cyber_incident("Massive 4.8 GB outbound exfiltration dump to external IP 185.220.101.7")
    assert res is not None
    assert res["did_steal_data"] is True
    assert "EXFILTRATION" in res["verdict"] or res["confidence_percent"] >= 50
    assert len(res["mitre_techniques"]) > 0
