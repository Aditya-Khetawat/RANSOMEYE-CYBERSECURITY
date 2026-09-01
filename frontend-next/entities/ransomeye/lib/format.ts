import type { Color } from "@tremor/react";
import type { RiskLevel, TelemetryEvent } from "../model/types";

/** Risk level -> Tremor colour, extended with "critical" beyond the usual
 * high/medium/low bucket. */
export const riskColor = (level: RiskLevel | string): Color => {
  switch (level?.toLowerCase()) {
    case "critical":
      return "rose";
    case "high":
      return "red";
    case "medium":
      return "amber";
    case "low":
      return "emerald";
    default:
      return "gray";
  }
};

export const factorLabel = (key: string): string =>
  ({
    encryption_pattern: "Encryption Pattern",
    process_behavior: "Process Behavior",
    privilege_escalation: "Privilege Escalation",
    network_abnormality: "Network Abnormality",
  })[key] ?? key;

/** Mirrors risk_engine.py WEIGHTS * 100 — the max a factor's weighted
 * contribution_pct can reach, used to normalize each factor's bar to its
 * own ceiling rather than a shared one. */
export const FACTOR_WEIGHT_MAX: Record<string, number> = {
  encryption_pattern: 35,
  process_behavior: 25,
  privilege_escalation: 20,
  network_abnormality: 20,
};

/** Simulated telemetry timestamps are naive local ISO strings. */
export const formatTickTime = (ts: string): string => {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
};

export const eventSummary = (ev: TelemetryEvent): string => {
  switch (ev.type) {
    case "file":
      if (ev.op === "rename" && ev.new_ext) return `Renamed ${ev.ext} -> ${ev.new_ext} (entropy ${ev.entropy.toFixed(2)})`;
      return `${ev.op[0].toUpperCase()}${ev.op.slice(1)} ${ev.ext} (entropy ${ev.entropy.toFixed(2)})`;
    case "process":
      return `${ev.image} spawned from ${ev.parent_image}${ev.suspicious_indicators.length ? ` — ${ev.suspicious_indicators.join(", ")}` : ""}`;
    case "network":
      return `${ev.reputation === "malicious" ? "⚠ " : ""}Outbound -> ${ev.dest_ip}:${ev.dest_port} (${ev.reputation})`;
    case "privilege":
      return `${ev.action}: ${ev.detail}`;
    default:
      return "Unknown event";
  }
};

export const eventIcon = (ev: TelemetryEvent): string => {
  switch (ev.type) {
    case "file":
      return "📄";
    case "process":
      return ev.suspicious_indicators.length ? "⚙️⚠" : "⚙️";
    case "network":
      return ev.reputation === "malicious" ? "🌐⚠" : "🌐";
    case "privilege":
      return "🔑";
    default:
      return "•";
  }
};
