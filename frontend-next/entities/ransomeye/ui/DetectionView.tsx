"use client";

import { useMemo } from "react";
import Link from "next/link";
import clsx from "clsx";
import { useScenario } from "../model/ScenarioContext";
import { computeDetectionWindow } from "../lib/attackStages";
import { buildEvidenceChain, deriveVerdict } from "../lib/evidenceChain";
import { PageHead, NeedsScenario, NeedsEndpoint } from "./pageParts";
import { RiskGauge } from "./RiskGauge";
import { BehaviorTimeline } from "./BehaviorTimeline";

const FACTOR_LABEL: Record<string, string> = {
  encryption_pattern: "Encryption pattern",
  process_behavior: "Process behavior",
  privilege_escalation: "Privilege escalation",
  network_abnormality: "Network abnormality",
};

const LEVEL_TONE: Record<string, string> = {
  critical: "text-red-600",
  high: "text-red-600",
  medium: "text-amber-600",
  low: "text-emerald-600",
};

export function DetectionView() {
  const { run, revealedTicks, selectedEndpointId, selectedState, activeAlerts } = useScenario();

  const alert = useMemo(
    () => activeAlerts.find((a) => a.endpoint_id === selectedEndpointId),
    [activeAlerts, selectedEndpointId]
  );

  const detection = useMemo(
    () => (selectedEndpointId ? computeDetectionWindow(revealedTicks, selectedEndpointId, alert) : null),
    [revealedTicks, selectedEndpointId, alert]
  );

  const verdict = useMemo(() => {
    if (!selectedEndpointId) return null;
    const items = buildEvidenceChain(revealedTicks, selectedEndpointId, selectedState);
    const peak = revealedTicks.reduce((m, t) => {
      const s = t.endpoint_states[selectedEndpointId]?.risk.score ?? 0;
      return Math.max(m, s);
    }, 0);
    return deriveVerdict(items, peak, selectedState?.risk.score ?? 0);
  }, [revealedTicks, selectedEndpointId, selectedState]);

  const renamesSeen = revealedTicks.some((t) =>
    (t.events_by_endpoint[selectedEndpointId ?? ""] ?? []).some(
      (e) => e.type === "file" && e.op === "rename" && e.new_ext
    )
  );

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="See"
        title="Ransomware Early Warning"
        sub="Detect the coordinated behavioral progression of ransomware before destructive impact — and show exactly which signals crossed the line."
      />

      <NeedsScenario>
        <NeedsEndpoint>
          {selectedState && verdict && (
            <>
              {/* live threat status */}
              <div className="grid gap-3 sm:grid-cols-4">
                <Stat
                  label="Threat level"
                  value={selectedState.risk.level.toUpperCase()}
                  className={LEVEL_TONE[selectedState.risk.level]}
                />
                <Stat label="Ransomware confidence" value={`${verdict.peakScore}%`} />
                <Stat
                  label="Detection lead time"
                  value={
                    detection?.leadSeconds == null
                      ? "—"
                      : detection.leadSeconds >= 60
                        ? `${Math.floor(detection.leadSeconds / 60)}m ${String(detection.leadSeconds % 60).padStart(2, "0")}s`
                        : `${detection.leadSeconds}s`
                  }
                  className="text-orange-600"
                />
                <Stat
                  label="Encryption status"
                  value={renamesSeen ? "IN PROGRESS" : "NOT STARTED"}
                  className={renamesSeen ? "text-red-600" : "text-emerald-600"}
                />
              </div>

              <div data-tour="detection-verdict" className="flex flex-col gap-4">
              {/* behavioral signals */}
              <div className="rounded-xl border border-gray-200 bg-white p-4">
                <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
                  Why RansomEye is concerned
                </div>
                <div className="flex flex-col gap-2.5">
                  {(Object.keys(FACTOR_LABEL) as (keyof typeof FACTOR_LABEL)[]).map((k) => {
                    const raw = selectedState.risk.factors[k as keyof typeof selectedState.risk.factors];
                    const pct = selectedState.risk.weighted_contribution_pct[
                      k as keyof typeof selectedState.risk.weighted_contribution_pct
                    ];
                    return (
                      <div key={k}>
                        <div className="mb-1 flex items-baseline justify-between text-xs">
                          <span className="font-medium text-gray-700">{FACTOR_LABEL[k]}</span>
                          <span className="font-mono tabular-nums text-gray-400">
                            +{pct.toFixed(1)} / 100 &nbsp;·&nbsp; {Math.round(raw * 100)}% of cap
                          </span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-gray-100">
                          <div
                            className={clsx(
                              "h-full rounded-full",
                              raw >= 0.6 ? "bg-red-500" : raw >= 0.3 ? "bg-amber-500" : "bg-emerald-500"
                            )}
                            style={{ width: `${Math.max(raw * 100, 2)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {selectedState.risk.ml_anomaly_score != null && (
                    <div className="pt-1 text-[11px] text-gray-400">
                      IsolationForest anomaly score {selectedState.risk.ml_anomaly_score.toFixed(2)} — corroborating,
                      never the primary driver of the score above.
                    </div>
                  )}
                </div>
              </div>

              {/* verdict */}
              <div
                className={clsx(
                  "rounded-xl border-2 p-4",
                  verdict.tone === "critical"
                    ? "border-red-400 bg-red-50"
                    : verdict.tone === "warning"
                      ? "border-amber-400 bg-amber-50"
                      : "border-emerald-400 bg-emerald-50"
                )}
              >
                <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-500">Correlated verdict</div>
                <div className="mt-0.5 text-lg font-bold text-gray-900">{verdict.label}</div>
                <p className="mt-1 text-sm text-gray-600">{verdict.reasoning}</p>
                <Link
                  href="/evidence"
                  className="mt-3 inline-block rounded-lg bg-gray-900 px-3 py-1.5 text-xs font-semibold text-white"
                >
                  View evidence →
                </Link>
              </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-[320px_1fr] items-start">
                <RiskGauge endpointId={selectedEndpointId!} risk={selectedState.risk} />
                <BehaviorTimeline ticks={revealedTicks} endpointId={selectedEndpointId!} />
              </div>
            </>
          )}
        </NeedsEndpoint>
      </NeedsScenario>
    </div>
  );
}

function Stat({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-3">
      <div className={clsx("font-mono text-xl font-bold tabular-nums", className ?? "text-gray-900")}>
        {value}
      </div>
      <div className="mt-0.5 text-[11px] font-semibold uppercase tracking-[0.1em] text-gray-500">{label}</div>
    </div>
  );
}
