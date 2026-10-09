import sqlite3
import os
DB_PATH = os.environ.get("SENTINEL_DB", "sentinel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,            -- ISO 8601 UTC
  source TEXT NOT NULL,        -- auth | network | web
  src_ip TEXT NOT NULL,
  dst_ip TEXT,
  dst_port INTEGER,
  username TEXT,
  action TEXT,                 -- login | connect | http
  status TEXT,                 -- success | failed | 200 | 404 ...
  bytes_out INTEGER DEFAULT 0,
  url TEXT,
  message TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  window_start TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  target TEXT,
  threat TEXT NOT NULL,
  risk INTEGER NOT NULL,       -- 0-100
  severity TEXT NOT NULL,      -- Low | Medium | High | Critical
  confidence REAL NOT NULL,
  anomaly_score REAL NOT NULL,
  mitre TEXT NOT NULL,         -- JSON list
  reasons TEXT NOT NULL,       -- JSON list (explainability)
  actions TEXT NOT NULL,       -- JSON list
  status TEXT NOT NULL DEFAULT 'New'
);

CREATE TABLE IF NOT EXISTS blocklist (
  ip TEXT PRIMARY KEY, blocked_at TEXT NOT NULL, alert_id INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT
);
"""

def get_conn():
    db_path = os.environ.get("SENTINEL_DB", DB_PATH)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as c:
        c.executescript(SCHEMA)
