"use client";

import { useMemo } from "react";
import clsx from "clsx";
import { useScenario } from "../model/ScenarioContext";
import { deriveAttackStages } from "../lib/attackStages";
import { buildEvidenceChain } from "../lib/evidenceChain";
import { PageHead, NeedsScenario, NeedsEndpoint } from "./pageParts";
import { EvidenceChain } from "./EvidenceChain";

export function EvidenceView() {
  const { revealedTicks, selectedEndpointId, selectedState, contained, activeAlerts } = useScenario();

  const alert = activeAlerts.find((a) => a.endpoint_id === selectedEndpointId);

  const stages = useMemo(
    () =>
      selectedEndpointId
        ? deriveAttackStages(revealedTicks, selectedEndpointId, alert, contained)
        : [],
    [revealedTicks, selectedEndpointId, alert, contained]
  );

  const timeline = useMemo(() => {
    if (!selectedEndpointId) return [];
    return buildEvidenceChain(revealedTicks, selectedEndpointId, selectedState)
      .filter((i) => i.observed && i.firstSeen)
      .map((i) => ({ ts: i.firstSeen as string, label: i.title, mitre: i.mitre?.id }))
      .sort((a, b) => a.ts.localeCompare(b.ts));
  }, [revealedTicks, selectedEndpointId, selectedState]);

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="Understand"
        title="Evidence"
        sub="Every ransomware verdict is backed by observable behavioral evidence — not a black-box score. Here is what was seen, when, and how much each signal moved the risk."
      />

      <NeedsScenario>
        <NeedsEndpoint>
          {selectedEndpointId && (
            <>
              {/* attack chain */}
              <div className="rounded-xl border border-gray-200 bg-white p-4">
                <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
                  Attack chain — observed progression
                </div>
                <ol className="flex flex-wrap items-center gap-x-1 gap-y-2">
                  {stages.map((s, i) => (
                    <li key={s.key} className="flex items-center">
                      <span
                        className={clsx(
                          "rounded-lg border px-2.5 py-1 text-xs font-medium",
                          s.observedAt
                            ? s.key === "contained"
                              ? "border-emerald-300 bg-emerald-50 text-emerald-700"
                              : s.key === "early_warning"
                                ? "border-orange-300 bg-orange-50 text-orange-700"
                                : "border-red-300 bg-red-50 text-red-700"
                            : "border-dashed border-gray-300 text-gray-400"
                        )}
                        title={s.observedAt ? new Date(s.observedAt).toLocaleTimeString() : "not observed"}
                      >
                        {s.label}
                        {!s.observedAt && " ·  not observed"}
                      </span>
                      {i < stages.length - 1 && <span className="mx-1 text-gray-300">→</span>}
                    </li>
                  ))}
                </ol>
              </div>

              {/* the full evidence chain (contribution + rationale + absences) */}
              <EvidenceChain
                ticks={revealedTicks}
                endpointId={selectedEndpointId}
                state={selectedState}
              />

              {/* chronological evidence timeline */}
              {timeline.length > 0 && (
                <div className="rounded-xl border border-gray-200 bg-white p-4">
                  <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
                    Evidence timeline
                  </div>
                  <ol className="relative ml-1 border-l border-gray-200">
                    {timeline.map((e, i) => (
                      <li key={i} className="mb-2 ml-4 last:mb-0">
                        <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-gray-300" />
                        <div className="flex items-baseline gap-3">
                          <span className="font-mono text-xs text-gray-400">
                            {new Date(e.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                          </span>
                          <span className="text-sm text-gray-700">{e.label}</span>
                          {e.mitre && (
                            <span className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
                              {e.mitre}
                            </span>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </>
          )}
        </NeedsEndpoint>
      </NeedsScenario>
    </div>
  );
}
