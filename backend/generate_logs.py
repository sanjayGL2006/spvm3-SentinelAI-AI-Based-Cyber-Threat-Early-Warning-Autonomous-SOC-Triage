"""Synthetic network/auth/web logs with injected attacks (for demo + testing)."""
import random
from datetime import datetime, timedelta, timezone
from db import get_conn, init_db

def _ip(rng): return f"10.0.{rng.randint(1,5)}.{rng.randint(2,250)}"

def generate(seed: int = 7):
    rng = random.Random(seed)
    init_db()
    rows = []
    day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    users = ["asha", "ravi", "meera", "kiran", "admin", "clerk01"]
    internal = [_ip(rng) for _ in range(40)]

    def add(ts, source, src, dst, port, user, action, status, b=0, url=None, msg=""):
        rows.append((ts.isoformat(), source, src, dst, port, user, action, status, b, url, msg))

    # --- normal traffic 08:00-12:00 ---
    t0 = day + timedelta(hours=8)
    for _ in range(1500):
        ts = t0 + timedelta(seconds=rng.randint(0, 4 * 3600))
        ip = rng.choice(internal)
        kind = rng.choice(["auth", "web", "web", "network"])
        if kind == "auth":
            ok = rng.random() > 0.04
            add(ts, "auth", ip, "10.0.9.10", 443, rng.choice(users), "login",
                "success" if ok else "failed", 0, None, "login")
        elif kind == "web":
            add(ts, "web", ip, "10.0.9.20", 443, None, "http",
                rng.choices(["200", "404", "500"], [90, 8, 2])[0], rng.randint(500, 40000),
                rng.choice(["/", "/services", "/forms", "/notices", "/search?q=tax"]))
        else:
            add(ts, "network", ip, "10.0.9.30", rng.choice([80, 443, 53, 22]), None,
                "connect", "success", rng.randint(200, 90000))

    # --- ATTACK 1: brute force on HR portal admin ---
    ts = t0 + timedelta(hours=1, minutes=20)
    for i in range(55):
        add(ts + timedelta(seconds=i * 3), "auth", "45.12.98.201", "10.0.9.10", 443,
            "admin", "login", "failed", 0, None, "invalid password")
    add(ts + timedelta(seconds=170), "auth", "45.12.98.201", "10.0.9.10", 443,
        "admin", "login", "success", 0, None, "login ok")

    # --- ATTACK 2: port scan ---
    ts = t0 + timedelta(hours=2, minutes=5)
    for i, port in enumerate(rng.sample(range(1, 10000), 180)):
        add(ts + timedelta(seconds=i * 0.5), "network", "185.220.101.7", "10.0.9.30",
            port, None, "connect", "failed", 60)

    # --- ATTACK 3: SQL injection on citizen portal ---
    ts = t0 + timedelta(hours=2, minutes=40)
    payloads = ["/search?q=' OR '1'='1", "/search?q=1 UNION SELECT user,pass FROM users--",
                "/forms?id=1; DROP TABLE users", "/notices?id=' OR 1=1 --", "/search?q=<script>alert(1)</script>"]
    for i in range(12):
        add(ts + timedelta(seconds=i * 7), "web", "103.77.12.9", "10.0.9.20", 443, None,
            "http", rng.choice(["500", "200", "403"]), 900, payloads[i % len(payloads)])

    # --- ATTACK 4: night-time data exfiltration (insider / compromised host) ---
    ts = day + timedelta(hours=2, minutes=10)
    for i in range(14):
        add(ts + timedelta(seconds=i * 20), "network", "10.0.3.77", "198.51.100.23", 443,
            None, "connect", "success", 60_000_000)

    # --- ATTACK 5: request flood on /login ---
    ts = t0 + timedelta(hours=3, minutes=10)
    for i in range(420):
        add(ts + timedelta(seconds=i * 0.2), "web", "91.200.12.4", "10.0.9.20", 443, None,
            "http", rng.choice(["200", "503"]), 300, "/login")

    with get_conn() as c:
        c.execute("DELETE FROM events")
        c.executemany("""INSERT INTO events(ts,source,src_ip,dst_ip,dst_port,username,
                      action,status,bytes_out,url,message) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", rows)

        counts = c.execute("SELECT source, COUNT(*) FROM events GROUP BY source").fetchall()
        print("\nRow count per source:")
        for row in counts:
            print(f"  - {row[0]}: {row[1]}")

    return len(rows)

if __name__ == "__main__":
    generate()

