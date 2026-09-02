"use client";

import { useMemo } from "react";
import clsx from "clsx";
import { TbCheck, TbShieldCheck, TbShieldHalf, TbAlertOctagon } from "react-icons/tb";
import type { EarlyWarningAlert, EndpointState, Endpoint, Tick } from "../model/types";
import { computeDetectionWindow, deriveAttackStages } from "../lib/attackStages";

type Posture = "protected" | "monitoring" | "under_attack" | "contained";

function derivePosture(
  states: Record<string, EndpointState>,
  alert: EarlyWarningAlert | undefined,
  contained: boolean
): Posture {
  if (alert && contained) return "contained";
  if (alert) return "under_attack";
  const anyElevated = Object.values(states).some((s) => s.risk.level === "medium" || s.risk.level === "high" || s.risk.level === "critical");
  return anyElevated ? "monitoring" : "protected";
}

const POSTURE_UI: Record<Posture, { label: string; cls: string; dot: string; Icon: typeof TbShieldCheck }> = {
  protected: {
    label: "PROTECTED",
    cls: "text-emerald-700 bg-emerald-50 border-emerald-300",
    dot: "bg-emerald-500",
    Icon: TbShieldCheck,
  },
  monitoring: {
    label: "MONITORING",
    cls: "text-amber-700 bg-amber-50 border-amber-300",
    dot: "bg-amber-500",
    Icon: TbShieldHalf,
  },
  under_attack: {
    label: "RANSOMWARE STAGING DETECTED",
    cls: "text-red-700 bg-red-50 border-red-400",
    dot: "bg-red-500 animate-pulse",
    Icon: TbAlertOctagon,
  },
  contained: {
    label: "THREAT CONTAINED",
    cls: "text-emerald-700 bg-emerald-50 border-emerald-400",
    dot: "bg-emerald-500",
    Icon: TbShieldCheck,
  },
};

function formatLead(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds === 0) return "0s";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}

function Metric({
  value,
  label,
  hint,
  tone = "default",
}: {
  value: string | number;
  label: string;
  hint?: string;
  tone?: "default" | "danger" | "good";
}) {
  return (
    <div className="min-w-0">
      <div
        className={clsx(
          "text-3xl sm:text-4xl font-bold tabular-nums tracking-tight",
          tone === "danger" && "text-red-600",
          tone === "good" && "text-emerald-600",
          tone === "default" && "text-gray-900"
        )}
      >
        {value}
      </div>
      <div className="text-[11px] font-semibold tracking-[0.12em] uppercase text-gray-500 mt-0.5">
        {label}
      </div>
      {hint && <div className="text-[11px] text-gray-400 mt-0.5 truncate">{hint}</div>}
    </div>
  );
}

/**
 * Command Center — the product's headline. Every number here is derived from
 * the live scenario run's real telemetry and risk output (see
 * lib/attackStages.ts), including the detection lead time, which is measured
 * against when encryption activity actually peaked rather than asserted.
 */
export function CommandCenter({
  endpoints,
  states,
  ticks,
  alert,
  contained,
  targetEndpointId,
}: {
  endpoints: Endpoint[];
  states: Record<string, EndpointState>;
  ticks: Tick[];
  alert: EarlyWarningAlert | undefined;
  contained: boolean;
  targetEndpointId: string | null;
}) {
  const posture = derivePosture(states, alert, contained);
  const ui = POSTURE_UI[posture];

  const counts = useMemo(() => {
    let healthy = 0;
    let suspicious = 0;
    let critical = 0;
    for (const ep of endpoints) {
      const level = states[ep.id]?.risk.level;
      // An endpoint that fired an early warning this run stays "critical"
      // until it's contained, even once its instantaneous risk decays —
      // encryption tapering off is not the same as the box being safe, and
      // a SOC view that flipped it back to healthy would be lying.
      const alerted = alert?.endpoint_id === ep.id && !contained;
      if (alerted || level === "high" || level === "critical") critical += 1;
      else if (level === "medium") suspicious += 1;
      else healthy += 1;
    }
    return { healthy, suspicious, critical };
  }, [endpoints, states, alert, contained]);

  const focusId = alert?.endpoint_id ?? targetEndpointId ?? endpoints[0]?.id ?? "";
  const stages = useMemo(
    () => deriveAttackStages(ticks, focusId, alert, contained),
    [ticks, focusId, alert, contained]
  );
  const { leadSeconds } = useMemo(
    () => computeDetectionWindow(ticks, focusId, alert),
    [ticks, focusId, alert]
  );

  // Files this endpoint had touched by the time the warning fired — the
  // concrete "damage so far" number, straight from the feature window.
  const filesAtAlert = alert
    ? ticks.find((t) => t.tick === alert.fired_at_tick)?.endpoint_states[focusId]?.feat.files_touched ?? null
    : null;

  return (
    <div className="rounded-xl border border-gray-200 bg-white overflow-hidden">
      <div className={clsx("flex items-center gap-2.5 px-4 sm:px-5 py-2.5 border-b", ui.cls)}>
        <span className={clsx("w-2 h-2 rounded-full shrink-0", ui.dot)} />
        <ui.Icon className="w-4 h-4 shrink-0" />
        <span className="text-xs font-bold tracking-[0.14em] uppercase">
          System Status: {ui.label}
        </span>
      </div>

      <div className="px-4 sm:px-5 py-4 grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric
          value={counts.healthy}
          label="Endpoints Healthy"
          tone="good"
          hint={`of ${endpoints.length} monitored`}
        />
        <Metric
          value={counts.suspicious}
          label="Suspicious"
          tone={counts.suspicious > 0 ? "danger" : "default"}
          hint="elevated, below alert threshold"
        />
        <Metric
          value={counts.critical}
          label="Critical"
          tone={counts.critical > 0 ? "danger" : "default"}
          hint="crossed the early-warning threshold"
        />
        <Metric
          value={formatLead(leadSeconds)}
          label="Detection Lead Time"
          tone={leadSeconds ? "good" : "default"}
          hint={
            leadSeconds
              ? "warned before encryption peaked"
              : alert
                ? "warning fired at peak activity"
                : "no threat detected"
          }
        />
      </div>

      <div className="px-4 sm:px-5 pb-4">
        <div className="text-[11px] font-semibold tracking-[0.12em] uppercase text-gray-500 mb-2">
          Kill Chain {focusId ? `· ${focusId}` : ""}
        </div>
        <ol className="flex flex-wrap items-stretch gap-1.5">
          {stages.map((stage) => {
            const seen = stage.observedAt !== null;
            const isWarning = stage.key === "early_warning";
            const isContained = stage.key === "contained";
            return (
              <li
                key={stage.key}
                className={clsx(
                  "flex-1 min-w-[8.5rem] rounded-lg border px-2.5 py-2 transition-colors",
                  !seen && "border-dashed border-gray-200 text-gray-400",
                  seen && isContained && "border-emerald-400 bg-emerald-50 text-emerald-800",
                  seen && isWarning && "border-red-400 bg-red-50 text-red-800",
                  seen && !isWarning && !isContained && "border-amber-300 bg-amber-50 text-amber-900"
                )}
              >
                <div className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide">
                  {seen && (isContained || isWarning) && <TbCheck className="w-3 h-3 shrink-0" />}
                  <span className="truncate">{stage.label}</span>
                </div>
                <div className="text-[11px] tabular-nums opacity-80 mt-0.5">
                  {seen
                    ? new Date(stage.observedAt as string).toLocaleTimeString(undefined, {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })
                    : "not observed"}
                </div>
              </li>
            );
          })}
        </ol>

        {alert && (
          <div className="mt-3 text-xs text-gray-600">
            {contained ? (
              <>
                Contained after <strong>{filesAtAlert ?? "—"}</strong> files touched on {focusId}. Encryption stopped before
                completion.
              </>
            ) : (
              <>
                Early warning fired with <strong>{filesAtAlert ?? "—"}</strong> files touched on {focusId} — approve
                containment below to stop it.
              </>
            )}
          </div>
        )}
        {!alert && (
          <div className="mt-3 text-xs text-gray-500">
            No ransomware kill-chain activity observed in this run. Elevated file or process activity alone does not
            trigger a warning — that is the false-positive control working.
          </div>
        )}
      </div>
    </div>
  );
}
