"""
replay.py — Phase 7 replay simulator.

Reads events from the SQLite events table (populated by generate_logs.py)
and re-posts them to POST /api/ingest in real time, compressed by a speed
multiplier so you can watch the dashboard update without waiting hours.

Usage (with backend running):
    python replay.py              # 60x faster than real time (default)
    python replay.py --speed 1    # real-time (1 second per log-second)
    python replay.py --speed 120  # very fast burn-through

The script is purely a demo tool — it does not touch the database directly;
all writes go through the ingest endpoint so the full validation path runs.
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone

INGEST_URL = "http://localhost:8000/api/ingest"
BATCH_SIZE = 50        # events per HTTP request
DEFAULT_SPEED = 60     # log-seconds per wall-second


def fetch_events() -> list[dict]:
    """Load all events from the DB via the backend (read-only path)."""
    # We import db here so the script can also run stand-alone inside venv.
    try:
        from db import get_conn  # type: ignore
        with get_conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM events ORDER BY ts")]
        return rows
    except Exception as exc:
        print(f"[replay] ERROR reading events from DB: {exc}", file=sys.stderr)
        return []


def post_batch(batch: list[dict]) -> dict:
    body = json.dumps(batch).encode()
    req = urllib.request.Request(
        INGEST_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"error": exc.read().decode(errors="replace")}
    except Exception as exc:
        return {"error": str(exc)}


def replay(speed: float) -> None:
    events = fetch_events()
    if not events:
        print("[replay] No events in DB — run 'python generate_logs.py' first.")
        return

    print(f"[replay] Replaying {len(events)} events at {speed}x speed → {INGEST_URL}")

    # Group events into logical time buckets (1-second resolution).
    buckets: dict[int, list[dict]] = defaultdict(list)
    epoch0: float | None = None
    for ev in events:
        try:
            dt = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
            epoch = int(dt.timestamp())
        except (ValueError, KeyError):
            continue
        if epoch0 is None:
            epoch0 = epoch
        buckets[epoch - int(epoch0)].append(ev)

    if not buckets:
        print("[replay] Could not parse any timestamps. Aborting.")
        return

    wall_start = time.monotonic()
    log_second = 0
    total_sent = total_inserted = 0
    pending: list[dict] = []

    for log_second in sorted(buckets.keys()):
        # Wait until the right wall-clock moment.
        target_wall = wall_start + log_second / speed
        sleep = target_wall - time.monotonic()
        if sleep > 0:
            time.sleep(sleep)

        pending.extend(buckets[log_second])

        # Send when we've accumulated enough or hit the end.
        while len(pending) >= BATCH_SIZE:
            batch, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]
            result = post_batch(batch)
            ins = result.get("inserted", 0)
            total_sent += len(batch)
            total_inserted += ins
            ts_now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            print(f"  [{ts_now}] log+{log_second:5d}s  sent={len(batch)}  "
                  f"inserted={ins}  dup={result.get('skipped_duplicate', 0)}")

    # Flush remainder.
    if pending:
        result = post_batch(pending)
        ins = result.get("inserted", 0)
        total_sent += len(pending)
        total_inserted += ins
        print(f"  [flush] sent={len(pending)}  inserted={ins}")

    print(f"\n[replay] Done. Total sent={total_sent}, inserted={total_inserted}, "
          f"skipped={total_sent - total_inserted}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI log replay simulator")
    parser.add_argument("--speed", type=float, default=DEFAULT_SPEED,
                        help=f"Replay speed multiplier (default {DEFAULT_SPEED})")
    args = parser.parse_args()
    if args.speed <= 0:
        print("--speed must be > 0")
        sys.exit(1)
    replay(args.speed)
