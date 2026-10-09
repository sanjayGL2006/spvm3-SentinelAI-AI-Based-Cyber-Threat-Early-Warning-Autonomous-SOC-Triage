"""
ingest.py — Phase 7: real-time ingestion helpers.

Responsibilities:
  - Validate and insert event batches from POST /api/ingest.
  - Deduplicate based on (ts, source, src_ip, dst_port, action, status).
  - Accept out-of-order timestamps; never reject an event just because it
    arrived late. Events are stored with their real ts, not arrival time.
  - After insertion, trigger a rolling-window re-analysis and push a
    Server-Sent Events (SSE) notification to every connected client.

SSE broadcaster
  - Clients subscribe at GET /api/stream.
  - Each alert-count update is broadcast as:
      event: alerts
      data: {"alert_count": N, "new_alerts": M}
  - Clients reconnect automatically (EventSource contract).
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

from db import get_conn

logger = logging.getLogger(__name__)

# ── SSE subscriber registry ─────────────────────────────────────────────────
# Each subscriber is an asyncio.Queue that receives dict payloads.
_subscribers: list[asyncio.Queue[dict[str, Any]]] = []


def subscribe() -> asyncio.Queue[dict[str, Any]]:
    """Register a new SSE client and return its queue."""
    q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
    _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue[dict[str, Any]]) -> None:
    """Remove a subscriber queue when the client disconnects."""
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


async def broadcast(payload: dict[str, Any]) -> None:
    """Push a payload to all connected SSE subscribers (non-blocking)."""
    dead: list[asyncio.Queue[dict[str, Any]]] = []
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            # Client is too slow — mark for removal, don't block.
            dead.append(q)
    for q in dead:
        unsubscribe(q)


# ── Deduplication ────────────────────────────────────────────────────────────
_DUP_KEY = "(ts, source, src_ip, dst_port, action, status)"

_DEDUP_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup
ON events(ts, source, src_ip, COALESCE(dst_port,-1),
          COALESCE(action,''), COALESCE(status,''));
"""


def ensure_dedup_index() -> None:
    """Create the dedup index if it does not already exist."""
    with get_conn() as c:
        c.executescript(_DEDUP_DDL)


# ── Batch validation helpers ─────────────────────────────────────────────────
REQUIRED_FIELDS = {"ts", "source", "src_ip"}
_MAX_IP_LEN = 45


def _parse_ts(raw: str) -> str:
    """Normalise ts to ISO-8601 UTC; raise ValueError on bad input."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()


def _coerce_row(raw: dict[str, Any]) -> tuple | None:
    """
    Validate and coerce one event dict.
    Returns an INSERT-ready tuple or None if the row is malformed.
    Malformed rows are skipped and logged; they never raise to the caller.
    """
    try:
        missing = REQUIRED_FIELDS - raw.keys()
        if missing:
            raise ValueError(f"missing fields: {missing}")

        ts = _parse_ts(str(raw["ts"]))
        source = str(raw["source"])[:20]
        src_ip = str(raw["src_ip"])[:_MAX_IP_LEN]

        dst_ip = str(raw["dst_ip"])[:_MAX_IP_LEN] if raw.get("dst_ip") else None
        dst_port_raw = raw.get("dst_port")
        dst_port = int(dst_port_raw) if dst_port_raw is not None else None
        if dst_port is not None and not (0 <= dst_port <= 65535):
            raise ValueError(f"dst_port out of range: {dst_port}")

        username = str(raw["username"])[:64] if raw.get("username") else None
        action = str(raw["action"])[:32] if raw.get("action") else None
        status = str(raw["status"])[:16] if raw.get("status") else None
        bytes_out_raw = raw.get("bytes_out", 0)
        bytes_out = int(bytes_out_raw) if bytes_out_raw is not None else 0
        url = str(raw["url"])[:512] if raw.get("url") else None
        message = str(raw["message"])[:512] if raw.get("message") else None

        return (ts, source, src_ip, dst_ip, dst_port, username,
                action, status, bytes_out, url, message)
    except (ValueError, TypeError, KeyError) as exc:
        logger.debug("Skipping malformed ingest row: %s — %s", raw, exc)
        return None


# ── Core ingest function ─────────────────────────────────────────────────────

def ingest_batch(raw_events: list[dict[str, Any]]) -> dict[str, int]:
    """
    Validate, deduplicate and store a batch of raw event dicts.

    Returns:
        {"received": N, "inserted": M, "skipped_malformed": K, "skipped_duplicate": D}

    Out-of-order events are accepted; they are stored by their actual ts and
    will be picked up by the next rolling-window analysis.
    """
    received = len(raw_events)
    rows = [r for r in (_coerce_row(e) for e in raw_events) if r is not None]
    skipped_malformed = received - len(rows)

    inserted = 0
    skipped_dup = 0
    with get_conn() as conn:
        for row in rows:
            try:
                conn.execute(
                    """INSERT INTO events
                       (ts, source, src_ip, dst_ip, dst_port, username,
                        action, status, bytes_out, url, message)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    row,
                )
                inserted += 1
            except Exception:
                # UNIQUE constraint violation = duplicate; any other error
                # is also skipped to keep the batch atomic-free (best-effort).
                skipped_dup += 1

    return {
        "received": received,
        "inserted": inserted,
        "skipped_malformed": skipped_malformed,
        "skipped_duplicate": skipped_dup,
    }
