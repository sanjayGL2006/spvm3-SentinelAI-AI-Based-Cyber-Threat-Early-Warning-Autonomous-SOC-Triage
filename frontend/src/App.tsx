import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { Alert, Severity, Stats, Status } from "./types";

const COLORS: Record<Severity, string> = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };
const STATUSES: Status[] = ["New", "Investigating", "Contained", "Resolved", "False Positive"];

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [a, s] = await Promise.all([api.alerts(), api.stats()]);
      setAlerts(a); setStats(s); setError("");
      setSelected(prev => (prev ? a.find(x => x.id === prev.id) ?? null : a[0] ?? null));
    } catch (e) { setError((e as Error).message); }
  }, []);

  // Phase 7 — SSE replaces 5-second polling.
  // On every "alerts" server event we do an immediate refresh.
  // A 30-second safety poll catches the case where SSE is unavailable.
  const [live, setLive] = useState(false);
  useEffect(() => {
    refresh(); // initial load

    // SSE connection
    const es = new EventSource(api.streamUrl());
    es.addEventListener("heartbeat", () => setLive(true));
    es.addEventListener("alerts", () => { setLive(true); refresh(); });
    es.onerror = () => setLive(false);

    // 30-second fallback poll (silent, does not show an error on its own)
    const fallback = setInterval(refresh, 30_000);

    return () => { es.close(); clearInterval(fallback); };
  }, [refresh]);


  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); await refresh(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div style={{ fontFamily: "system-ui", background: "#0b1220", color: "#e5e7eb", minHeight: "100vh", padding: 16 }}>
      <header style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <h1 style={{ margin: 0 }}>🛡️ SentinelAI <small style={{ fontSize: 14, opacity: .6 }}>Cyber Threat Early Warning</small>
          {" "}<span title={live ? "Live stream connected" : "Connecting…"}
                style={{ fontSize: 11, padding: "2px 8px", borderRadius: 10,
                         background: live ? "#16a34a" : "#374151", color: "#fff" }}>
            {live ? "● LIVE" : "○ connecting…"}
          </span>
        </h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button disabled={busy} onClick={() => run(api.demo)}>▶ Run demo simulation</button>
          <label style={{ cursor: "pointer", border: "1px solid #475569", padding: "4px 10px", borderRadius: 6 }}>
            Upload CSV logs
            <input type="file" accept=".csv" hidden onChange={e => { const f = e.target.files?.[0]; if (f) run(() => api.upload(f)); }} />
          </label>
        </div>
      </header>

      {error && <p role="alert" style={{ color: "#fca5a5" }}>⚠ {error} (is the backend running on :8000?)</p>}

      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 12, margin: "16px 0" }}>
        <Card label="Events analysed" value={stats?.events ?? 0} />
        {(["Critical", "High", "Medium", "Low"] as Severity[]).map(s =>
          <Card key={s} label={s} value={stats?.by_severity[s] ?? 0} color={COLORS[s]} />)}
        <Card label="IPs blocked (sim.)" value={stats?.blocked_ips ?? 0} />
      </section>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))", gap: 16 }}>
        <div style={{ overflowX: "auto" }}>
          <h3>Prioritised alerts</h3>
          {alerts.length === 0 && <p style={{ opacity: .6 }}>No alerts yet. Click “Run demo simulation”.</p>}
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <tbody>
              {alerts.map(a => (
                <tr key={a.id} onClick={() => setSelected(a)}
                    style={{ cursor: "pointer", background: selected?.id === a.id ? "#1e293b" : "transparent", borderBottom: "1px solid #1f2937" }}>
                  <td style={{ padding: 8 }}><Badge sev={a.severity} /></td>
                  <td>{a.threat}<br /><small style={{ opacity: .6 }}>{a.src_ip}</small></td>
                  <td><b>{a.risk}</b>/100</td>
                  <td><small>{a.status}</small></td>
                </tr>))}
            </tbody>
          </table>
        </div>

        {selected && (
          <aside style={{ background: "#111827", padding: 16, borderRadius: 10 }}>
            <h3 style={{ marginTop: 0 }}>Incident #{selected.id} — {selected.threat} <Badge sev={selected.severity} /></h3>
            <p>Source <b>{selected.src_ip}</b> → Target <b>{selected.target ?? "n/a"}</b><br />
               Risk <b>{selected.risk}</b>/100 · Model confidence {(selected.confidence * 100).toFixed(0)}% · Anomaly score {selected.anomaly_score}</p>
            <h4>Why this alert was raised</h4>
            <ul>{selected.reasons.map(r => <li key={r}>{r}</li>)}</ul>
            <h4>MITRE ATT&amp;CK</h4>
            <ul>{selected.mitre.map(m => <li key={m}>{m}</li>)}</ul>
            <h4>Recommended actions</h4>
            <ol>{selected.actions.map(r => <li key={r}>{r}</li>)}</ol>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button disabled={busy || selected.status === "Contained"} onClick={() => run(() => api.respond(selected.id))}>🚫 Contain (simulated block)</button>
              <select value={selected.status} onChange={e => run(() => api.setStatus(selected.id, e.target.value as Status))}>
                {STATUSES.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </aside>
        )}
      </div>

      {stats && stats.top_sources.length > 0 && (
        <section><h3>Top risky sources</h3>
          {stats.top_sources.map(s => (
            <div key={s.src_ip} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <code style={{ width: 130 }}>{s.src_ip}</code>
              <div style={{ background: "#ef4444", height: 10, width: `${s.risk}%`, maxWidth: "60%", borderRadius: 5 }} />
              <small>{s.risk}</small>
            </div>))}
        </section>)}
    </div>
  );
}

const Card = ({ label, value, color }: { label: string; value: number; color?: string }) => (
  <div style={{ background: "#111827", padding: 12, borderRadius: 10, borderTop: `3px solid ${color ?? "#3b82f6"}` }}>
    <div style={{ fontSize: 26, fontWeight: 700 }}>{value}</div><small style={{ opacity: .7 }}>{label}</small>
  </div>);
const Badge = ({ sev }: { sev: Severity }) =>
  <span style={{ background: COLORS[sev], color: "#000", padding: "2px 8px", borderRadius: 12, fontSize: 12, fontWeight: 700 }}>{sev}</span>;
