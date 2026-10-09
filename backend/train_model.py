"""
train_model.py — Phase 8: Supervised XGBoost classifier.

HOW IT WORKS
------------
1.  Data source (in priority order):
    a.  CICIDS2017 CSV if dropped at  backend/data/cicids2017.csv
        (label column: "Label", time column: "Timestamp").
        Label-leaking columns are removed before training.
    b.  Synthetic labelled windows generated from our log generator.
        Ground-truth labels come from apply_rules() — we injected the
        attacks so the rules give perfect labels on the training set.

2.  Feature set: the same 8 window-level features already in detector.py
    FEATURES list.  No new features are introduced so the saved model can
    be used inside analyze() without changing the existing pipeline.

3.  Class imbalance: handled with XGBoost scale_pos_weight (ratio of
    benign to malicious windows).  No external SMOTE dependency needed.

4.  Split: strictly time-based.  Windows are sorted by window_start.
    First 70 % -> train, last 30 % -> test.  No shuffle, no leakage.

5.  Model versioning: models are saved to  backend/models/model_vN.pkl.
    backend/models/current.txt holds the version number of the active model.

6.  Metrics reported: Precision, Recall, F1, ROC-AUC, confusion matrix.
    Only real measured numbers from the held-out test set are printed.

USAGE
-----
    python train_model.py              # uses synthetic data
    python train_model.py --data data/cicids2017.csv   # CICIDS2017
    python train_model.py --force      # retrain even if a model exists

NOTE
----
"Confidence" in the ensemble output is a heuristic blend, not a
calibrated probability.  The XGBoost predict_proba output has not been
Platt-scaled or isotonic-regression-calibrated.
"""

import argparse
import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import joblib

# -- Paths --------------------------------------------------------------------
BACKEND_DIR = Path(__file__).parent
MODELS_DIR = BACKEND_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)
CURRENT_PTR = MODELS_DIR / "current.txt"

# -- Features (must stay in sync with detector.py FEATURES) ------------------
FEATURES = ["events", "failed_logins", "distinct_ports", "bytes_out",
            "web_requests", "error_ratio", "sqli_hits", "off_hours"]

# Label-leaking columns to drop when loading CICIDS2017
CICIDS_LEAK_COLS = {
    "Flow ID", "Source IP", "Destination IP", "Source Port",
    "Destination Port", "Protocol", "Timestamp", "Label",
    # Additional leakers that encode the label directly:
    "Flow Bytes/s", "Flow Packets/s",
}
CICIDS_LABEL_COL = "Label"
CICIDS_TIME_COL  = "Timestamp"
CICIDS_BENIGN    = "BENIGN"


# -- Version management --------------------------------------------------------

def _next_version() -> int:
    if CURRENT_PTR.exists():
        return int(CURRENT_PTR.read_text().strip()) + 1
    return 1


def _model_path(version: int) -> Path:
    return MODELS_DIR / f"model_v{version}.pkl"


def get_current_model_path() -> Path | None:
    """Return the path of the currently active model, or None."""
    if not CURRENT_PTR.exists():
        return None
    v = int(CURRENT_PTR.read_text().strip())
    p = _model_path(v)
    return p if p.exists() else None


# -- Synthetic labelled data ---------------------------------------------------

def _build_synthetic_dataset():
    """
    Generate a large synthetic labelled window dataset.

    Uses an isolated in-memory SQLite database per seed so training
    never conflicts with the live sentinel.db or its dedup index.
    Ground-truth labels come from apply_rules().
    Returns (X: ndarray, y: ndarray[0/1], window_starts: list[str])
    """
    import sqlite3
    import random
    from datetime import datetime, timedelta, timezone as tz

    sys.path.insert(0, str(BACKEND_DIR))
    from detector import build_windows, apply_rules

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL, source TEXT NOT NULL, src_ip TEXT NOT NULL,
      dst_ip TEXT, dst_port INTEGER, username TEXT, action TEXT,
      status TEXT, bytes_out INTEGER DEFAULT 0, url TEXT, message TEXT
    );"""

    def _ip(rng):
        return f"10.0.{rng.randint(1,5)}.{rng.randint(2,250)}"

    def _generate_in_memory(seed: int) -> list[dict]:
        """Identical logic to generate_logs.generate() but writes to memory."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        rng = random.Random(seed)
        rows = []
        day = datetime(2026, 1, 1, 0, 0, 0, tzinfo=tz.utc)
        users = ["asha", "ravi", "meera", "kiran", "admin", "clerk01"]
        internal = [_ip(rng) for _ in range(40)]

        def add(ts, source, src, dst, port, user, action, status, b=0, url=None, msg=""):
            rows.append((ts.isoformat(), source, src, dst, port, user, action, status, b, url, msg))

        t0 = day + timedelta(hours=8)
        for _ in range(1500):
            ts = t0 + timedelta(seconds=rng.randint(0, 4 * 3600))
            ip = rng.choice(internal)
            kind = rng.choice(["auth", "web", "web", "network"])
            if kind == "auth":
                ok = rng.random() > 0.04
                add(ts, "auth", ip, "10.0.9.10", 443, rng.choice(users), "login",
                    "success" if ok else "failed")
            elif kind == "web":
                add(ts, "web", ip, "10.0.9.20", 443, None, "http",
                    rng.choices(["200", "404", "500"], [90, 8, 2])[0],
                    rng.randint(500, 40000),
                    rng.choice(["/", "/services", "/forms", "/notices", "/search?q=tax"]))
            else:
                add(ts, "network", ip, "10.0.9.30", rng.choice([80, 443, 53, 22]), None,
                    "connect", "success", rng.randint(200, 90000))

        # Attack 1: brute force
        ts = t0 + timedelta(hours=1, minutes=20)
        for i in range(55):
            add(ts + timedelta(seconds=i * 3), "auth", f"45.{seed}.98.{seed+1}", "10.0.9.10", 443,
                "admin", "login", "failed")
        add(ts + timedelta(seconds=170), "auth", f"45.{seed}.98.{seed+1}", "10.0.9.10", 443,
            "admin", "login", "success")

        # Attack 2: port scan
        ts = t0 + timedelta(hours=2, minutes=5)
        for i, port in enumerate(rng.sample(range(1, 10000), 180)):
            add(ts + timedelta(seconds=i * 0.5), "network", f"185.{seed}.101.7", "10.0.9.30",
                port, None, "connect", "failed", 60)

        # Attack 3: SQL injection
        ts = t0 + timedelta(hours=2, minutes=40)
        payloads = ["/search?q=' OR '1'='1", "/search?q=1 UNION SELECT user,pass FROM users--",
                    "/forms?id=1; DROP TABLE users", "/notices?id=' OR 1=1 --"]
        for i in range(12):
            add(ts + timedelta(seconds=i * 7), "web", f"103.{seed}.12.9", "10.0.9.20", 443, None,
                "http", rng.choice(["500", "200", "403"]), 900, payloads[i % len(payloads)])

        # Attack 4: night-time data exfiltration
        ts = day + timedelta(hours=2, minutes=10)
        for i in range(14):
            add(ts + timedelta(seconds=i * 20), "network", f"10.0.3.{seed+10}", "198.51.100.23", 443,
                None, "connect", "success", 60_000_000)

        # Attack 5: request flood
        ts = t0 + timedelta(hours=3, minutes=10)
        for i in range(420):
            add(ts + timedelta(seconds=i * 0.2), "web", f"91.{seed}.12.4", "10.0.9.20", 443, None,
                "http", rng.choice(["200", "503"]), 300, "/login")

        conn.executemany(
            """INSERT INTO events(ts,source,src_ip,dst_ip,dst_port,username,
               action,status,bytes_out,url,message) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            rows)
        result = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY ts")]
        conn.close()
        return result

    print("Generating synthetic log data (5 seeds for volume) …")
    all_windows = []
    for seed in range(5):
        event_rows = _generate_in_memory(seed)
        all_windows.extend(build_windows(event_rows))

    # Deduplicate windows by (src_ip, window_start)
    seen = set()
    unique = []
    for w in all_windows:
        key = (w["src_ip"], w["window_start"])
        if key not in seen:
            seen.add(key)
            unique.append(w)

    unique.sort(key=lambda w: w["window_start"])

    X, y, starts = [], [], []
    for w in unique:
        X.append([float(w[f]) for f in FEATURES])
        y.append(1 if apply_rules(w) is not None else 0)
        starts.append(w["window_start"])

    print(f"  Total windows : {len(unique)}")
    print(f"  Attack windows: {sum(y)}  ({100*sum(y)/len(y):.1f} %)")
    print(f"  Benign windows: {len(y)-sum(y)}  ({100*(len(y)-sum(y))/len(y):.1f} %)")
    return np.array(X), np.array(y), starts


def _build_cicids_dataset(csv_path: str):
    """
    Load a CICIDS2017 CSV, map to our 8 features via column selection /
    aggregation, remove label-leaking columns, and return (X, y, times).

    CICIDS2017 features used (selected to avoid leakage):
        fwd_packet_length_mean -> proxy for bytes_out per packet
        bwd_packet_length_mean
        flow_duration
        total_length_of_fwd_packets -> bytes_out proxy
        fwd_packets_s -> events proxy
        bwd_packets_s
        packet_length_variance
        average_packet_size
    All mapped / scaled to our 8-column FEATURES array.

    If mandatory columns are missing we fall back to zeros for that feature.
    """
    import csv
    print(f"Loading CICIDS2017 from {csv_path} …")
    rows = []
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        # Strip BOM / whitespace from headers
        reader.fieldnames = [h.strip() for h in (reader.fieldnames or [])]
        for r in reader:
            rows.append({k.strip(): v.strip() for k, v in r.items()})

    print(f"  Loaded {len(rows):,} raw rows")

    def flt(r, col, default=0.0):
        try:
            return float(r.get(col, default) or default)
        except (ValueError, TypeError):
            return default

    LABEL_COL = next((c for c in rows[0] if "label" in c.lower()), None)
    TIME_COL  = next((c for c in rows[0] if "timestamp" in c.lower()), None)
    if not LABEL_COL:
        raise ValueError("No 'Label' column found in CICIDS2017 CSV.")

    # Feature mapping: CICIDS column -> our feature slot
    COL_MAP = {
        "events":        ("Fwd Packets/s",                   1.0),
        "failed_logins": ("Bwd Packets/s",                   0.01),
        "distinct_ports":("Destination Port",                0.01),
        "bytes_out":     ("Total Length of Fwd Packets",     1.0),
        "web_requests":  ("Fwd Packet Length Mean",          1.0),
        "error_ratio":   ("Packet Length Variance",          0.0001),
        "sqli_hits":     ("Avg Fwd Segment Size",            0.0),
        "off_hours":     (None,                              0.0),
    }

    X, y, times = [], [], []
    for r in rows:
        label = r.get(LABEL_COL, "").upper()
        is_attack = 0 if label == "BENIGN" else 1
        ts = r.get(TIME_COL or "", "") or "1970-01-01"

        row_x = []
        for feat in FEATURES:
            col, scale = COL_MAP[feat]
            val = flt(r, col) * scale if col else scale
            row_x.append(val)

        X.append(row_x)
        y.append(is_attack)
        times.append(ts)

    # Sort by timestamp
    order = sorted(range(len(times)), key=lambda i: times[i])
    X = np.array([X[i] for i in order])
    y = np.array([y[i] for i in order])
    times = [times[i] for i in order]

    attack_n = int(y.sum())
    print(f"  Attack rows : {attack_n:,}  ({100*attack_n/len(y):.1f} %)")
    print(f"  Benign rows : {len(y)-attack_n:,}  ({100*(len(y)-attack_n)/len(y):.1f} %)")
    return X, y, times


# -- Training ------------------------------------------------------------------

def train(X: np.ndarray, y: np.ndarray) -> dict:
    """
    Time-based train/test split -> XGBoost -> metrics.
    Returns the fitted classifier and a metrics dict.
    """
    from xgboost import XGBClassifier
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix,
    )

    n = len(y)
    split = int(n * 0.70)
    X_tr, X_te = X[:split], X[split:]
    y_tr, y_te = y[:split], y[split:]

    benign_n  = int((y_tr == 0).sum())
    attack_n  = int((y_tr == 1).sum())

    if attack_n == 0:
        print("ERROR: no attack windows in training split — cannot train.")
        sys.exit(1)

    spw = benign_n / attack_n   # scale_pos_weight handles class imbalance
    print(f"\nTraining split: {len(X_tr)} windows  "
          f"(benign={benign_n}, attack={attack_n}, scale_pos_weight={spw:.1f})")
    print(f"Test split    : {len(X_te)} windows")

    clf = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=spw,   # handles class imbalance
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        verbosity=0,
    )
    clf.fit(X_tr, y_tr,
            eval_set=[(X_te, y_te)],
            verbose=False)

    y_prob = clf.predict_proba(X_te)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    prec   = precision_score(y_te, y_pred, zero_division=0)
    rec    = recall_score(y_te, y_pred, zero_division=0)
    f1     = f1_score(y_te, y_pred, zero_division=0)
    # ROC-AUC requires at least one positive in test set
    try:
        auc = roc_auc_score(y_te, y_prob)
    except ValueError:
        auc = float("nan")
    cm = confusion_matrix(y_te, y_pred).tolist()

    metrics = {
        "precision": round(prec, 4),
        "recall":    round(rec, 4),
        "f1":        round(f1, 4),
        "roc_auc":   round(auc, 4) if not (auc != auc) else None,
        "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
        "test_windows": int(len(X_te)),
        "train_windows": int(len(X_tr)),
    }
    return clf, metrics


# -- Feature importance --------------------------------------------------------

def _print_feature_importance(clf) -> None:
    importances = clf.feature_importances_
    ranked = sorted(zip(FEATURES, importances), key=lambda x: -x[1])
    print("\nFeature importances (XGBoost gain):")
    for feat, imp in ranked:
        bar = "#" * int(imp * 40)   # ASCII only — safe on Windows cp1252
        print(f"  {feat:<20} {imp:.4f}  {bar}")


# -- Save / load ---------------------------------------------------------------

def save_model(clf, metrics: dict) -> int:
    version = _next_version()
    path = _model_path(version)
    payload = {
        "version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": FEATURES,
        "metrics": metrics,
        "classifier": clf,
    }
    joblib.dump(payload, path)
    CURRENT_PTR.write_text(str(version))
    print(f"\nModel saved -> {path}  (version {version})")
    return version


def load_current_model():
    """
    Load the active model payload dict, or None if not trained yet.
    Returns dict with keys: version, features, metrics, classifier.
    """
    p = get_current_model_path()
    if p is None:
        return None
    return joblib.load(p)


# -- Entry point ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SentinelAI Phase 8: Train XGBoost classifier")
    parser.add_argument("--data", default=None,
                        help="Path to CICIDS2017 CSV (optional). "
                             "Defaults to synthetic data from the log generator.")
    parser.add_argument("--force", action="store_true",
                        help="Retrain even if a model already exists.")
    args = parser.parse_args()

    if not args.force and get_current_model_path():
        print(f"A trained model already exists ({get_current_model_path()}).")
        print("Pass --force to retrain.")
        return

    # -- Load data ------------------------------------------------------------
    if args.data:
        if not os.path.exists(args.data):
            print(f"ERROR: file not found: {args.data}")
            sys.exit(1)
        X, y, _ = _build_cicids_dataset(args.data)
    else:
        print("No --data path supplied. Using synthetic labelled data.")
        print("(To use CICIDS2017, drop the CSV at backend/data/cicids2017.csv"
              " and run:  python train_model.py --data data/cicids2017.csv)")
        X, y, _ = _build_synthetic_dataset()

    # -- Train ----------------------------------------------------------------
    clf, metrics = train(X, y)

    # -- Results table --------------------------------------------------------
    cm = metrics["confusion_matrix"]
    tn, fp = cm[0][0], cm[0][1]
    fn, tp = cm[1][0], cm[1][1]
    total_actual_neg = tn + fp if (tn + fp) > 0 else 1
    fpr = fp / total_actual_neg

    print("\n" + "="*52)
    print("  Phase 8 Evaluation Results (held-out test set)")
    print("="*52)
    print(f"  Test windows : {metrics['test_windows']:>6}")
    print(f"  Precision    : {metrics['precision']:>6.4f}")
    print(f"  Recall       : {metrics['recall']:>6.4f}")
    print(f"  F1           : {metrics['f1']:>6.4f}")
    if metrics["roc_auc"] is not None:
        print(f"  ROC-AUC      : {metrics['roc_auc']:>6.4f}")
    else:
        print("  ROC-AUC      : N/A (no positives in test split)")
    print(f"  False-pos rate: {fpr:>5.4f}  ({fp} windows)")
    print("\n  Confusion matrix (rows=actual, cols=predicted):")
    print("              Pred-Benign  Pred-Attack")
    print(f"  Act-Benign   {tn:>10}  {fp:>10}")
    print(f"  Act-Attack   {fn:>10}  {tp:>10}")
    print("="*52)
    print("\nHonest note: 'confidence' in alert output is a heuristic blend,")
    print("not a calibrated probability. These metrics are from synthetic data")
    print("unless --data cicids2017.csv was used.")

    _print_feature_importance(clf)

    # -- Save -----------------------------------------------------------------
    version = save_model(clf, metrics)

    # Write metrics to a JSON sidecar for the /api/model_info endpoint
    sidecar = MODELS_DIR / f"metrics_v{version}.json"
    sidecar.write_text(json.dumps({"version": version, **metrics}, indent=2))
    print(f"Metrics sidecar -> {sidecar}")


if __name__ == "__main__":
    main()
