import type { EarlyWarningAlert, Tick } from "../model/types";

export type StageKey =
  | "initial_access"
  | "privilege_escalation"
  | "shadow_copy_deletion"
  | "c2_beacon"
  | "mass_encryption"
  | "early_warning"
  | "contained";

export interface StageStatus {
  key: StageKey;
  label: string;
  /** ISO timestamp of the first tick this stage's evidence was observed,
   * or null if not (yet) observed in the revealed ticks. */
  observedAt: string | null;
}

const STAGE_LABELS: Record<StageKey, string> = {
  initial_access: "Initial Access",
  privilege_escalation: "Privilege Escalation",
  shadow_copy_deletion: "Shadow Copy Deletion",
  c2_beacon: "C2 Beacon",
  mass_encryption: "Mass Encryption",
  early_warning: "Early Warning",
  contained: "Contained",
};

/**
 * Derives which real ransomware kill-chain stages have actually been
 * observed for one endpoint, from the raw telemetry events themselves —
 * never fabricated. Each stage lights up the instant its underlying
 * evidence (a specific process indicator, privilege action, network
 * reputation, or file-rename pattern) appears anywhere in the revealed
 * ticks. On SUSPICIOUS_ACTIVITY or NORMAL_ACTIVITY, none of the
 * ransomware-specific stages ever light up — that's the honest signal
 * this endpoint isn't actually being encrypted.
 */
export function deriveAttackStages(
  ticks: Tick[],
  endpointId: string,
  alert: EarlyWarningAlert | undefined,
  contained: boolean
): StageStatus[] {
  const firstSeen: Partial<Record<StageKey, string>> = {};
  const mark = (key: StageKey, ts: string) => {
    if (!firstSeen[key]) firstSeen[key] = ts;
  };

  for (const tick of ticks) {
    for (const ev of tick.events_by_endpoint[endpointId] ?? []) {
      if (ev.type === "process") {
        if (ev.suspicious_indicators.some((i) => i === "encoded_command" || i === "spawned_from_office_macro")) {
          mark("initial_access", ev.ts);
        }
        if (ev.suspicious_indicators.includes("shadow_copy_deletion")) {
          mark("shadow_copy_deletion", ev.ts);
        }
      }
      if (ev.type === "privilege") {
        if (ev.action === "token_elevation") mark("privilege_escalation", ev.ts);
        if (ev.action === "shadow_copy_delete") mark("shadow_copy_deletion", ev.ts);
      }
      if (ev.type === "network" && ev.reputation === "malicious") {
        mark("c2_beacon", ev.ts);
      }
      if (ev.type === "file" && ev.op === "rename" && ev.new_ext) {
        mark("mass_encryption", ev.ts);
      }
    }
  }

  if (alert) mark("early_warning", alert.timestamp);
  if (contained && alert) mark("contained", alert.timestamp);

  const order: StageKey[] = [
    "initial_access",
    "privilege_escalation",
    "shadow_copy_deletion",
    "mass_encryption",
    "c2_beacon",
    "early_warning",
    "contained",
  ];

  return order.map((key) => ({
    key,
    label: STAGE_LABELS[key],
    observedAt: firstSeen[key] ?? null,
  }));
}

export interface DetectionWindow {
  /** Seconds of lead time between the early warning and the point mass
   * encryption activity actually peaked on this endpoint. Null when there's
   * no alert (nothing detected) or not enough data yet to compute it. */
  leadSeconds: number | null;
}

/** How much advance warning RansomEye actually gave: the gap between when
 * the alert fired and the tick where this endpoint's file-modification +
 * rename rate (the encryption-in-progress signal) peaked. Computed from the
 * real per-tick feature history — never a fixed/marketing number. */
export function computeDetectionWindow(ticks: Tick[], endpointId: string, alert: EarlyWarningAlert | undefined): DetectionWindow {
  if (!alert) return { leadSeconds: null };

  let peakTick = alert.fired_at_tick;
  let peakRate = -1;
  for (const tick of ticks) {
    const feat = tick.endpoint_states[endpointId]?.feat;
    if (!feat) continue;
    const rate = feat.file_mod_rate + feat.file_rename_rate;
    if (rate > peakRate) {
      peakRate = rate;
      peakTick = tick.tick;
    }
  }

  const tickSeconds = 30; // matches backend TICK_SECONDS
  const leadSeconds = (peakTick - alert.fired_at_tick) * tickSeconds;
  return { leadSeconds: Math.max(leadSeconds, 0) };
}
