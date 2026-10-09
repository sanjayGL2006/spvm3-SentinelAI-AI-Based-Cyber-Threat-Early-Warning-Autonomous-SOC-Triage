import type { Alert, Stats, Status } from "./types";
const BASE = "http://localhost:8000/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? res.statusText);
  return res.json() as Promise<T>;
}
export const api = {
  alerts: () => req<Alert[]>("/alerts"),
  stats: () => req<Stats>("/stats"),
  demo: () => req<{ events: number; alerts: number }>("/demo/generate", { method: "POST" }),
  upload: (f: File) => { const fd = new FormData(); fd.append("file", f);
    return req<{ events: number; alerts: number }>("/upload", { method: "POST", body: fd }); },
  setStatus: (id: number, status: Status) => req(`/alerts/${id}/status`, {
    method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) }),
  respond: (id: number) => req<{ blocked: string; simulated: boolean }>(`/alerts/${id}/respond`, { method: "POST" }),
  // Phase 7
  ingest: (events: object[]) => req<{ received: number; inserted: number; skipped_malformed: number; skipped_duplicate: number }>(
    "/ingest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }) }),
  streamUrl: () => `${BASE}/stream`,
};
