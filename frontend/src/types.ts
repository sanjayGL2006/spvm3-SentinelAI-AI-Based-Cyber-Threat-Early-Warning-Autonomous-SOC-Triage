export type Severity = "Low" | "Medium" | "High" | "Critical";
export type Status = "New" | "Investigating" | "Contained" | "Resolved" | "False Positive";

export interface Alert {
  id: number; created_at: string; window_start: string; src_ip: string; target: string | null;
  threat: string; risk: number; severity: Severity; confidence: number; anomaly_score: number;
  mitre: string[]; reasons: string[]; actions: string[]; status: Status;
}
export interface Stats {
  events: number; blocked_ips: number;
  by_severity: Partial<Record<Severity, number>>;
  by_threat: Record<string, number>;
  top_sources: { src_ip: string; risk: number; alerts: number }[];
}
