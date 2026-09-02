"use client";

import { useMemo } from "react";
import Link from "next/link";
import clsx from "clsx";
import { TbCheck } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";
import { buildEvidenceChain } from "../lib/evidenceChain";
import { PageHead, NeedsScenario } from "./pageParts";
import { EndpointFleetGrid } from "./EndpointFleetGrid";
import { NetworkTopology } from "./NetworkTopology";

export function FleetView() {
  const {
    run,
    currentStates,
    revealedTicks,
    activeAlerts,
    contained,
    selectedEndpointId,
    selectEndpoint,
    selectedState,
  } = useScenario();

  const counts = useMemo(() => {
    let healthy = 0,
      suspicious = 0,
      critical = 0;
    for (const ep of run?.endpoints ?? []) {
      const lvl = currentStates[ep.id]?.risk.level;
      if (lvl === "critical" || lvl === "high") critical++;
      else if (lvl === "medium") suspicious++;
      else healthy++;
    }
    const isolated = contained && activeAlerts[0] ? 1 : 0;
    return { healthy, suspicious, critical, isolated };
  }, [run, currentStates, contained, activeAlerts]);

  const evidence = useMemo(
    () =>
      selectedEndpointId
        ? buildEvidenceChain(revealedTicks, selectedEndpointId, selectedState).filter(
            (i) => i.key !== "file_churn"
          )
        : [],
    [revealedTicks, selectedEndpointId, selectedState]
  );

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="See"
        title="Endpoint Fleet"
        sub="Continuous ransomware risk across protected endpoints, and the real domain-isolation state — not a predicted spread map."
      />

      <NeedsScenario>
        {run && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Tally n={counts.healthy} label="Protected" tone="good" />
              <Tally n={counts.suspicious} label="Suspicious" tone="warn" />
              <Tally n={counts.critical} label="Critical" tone="bad" />
              <Tally n={counts.isolated} label="Isolated" tone="default" />
            </div>

            <div className="grid gap-4 lg:grid-cols-[1fr_360px] items-start">
              <NetworkTopology
                endpoints={run.endpoints}
                states={currentStates}
                alert={activeAlerts[0]}
                contained={contained}
                selectedEndpointId={selectedEndpointId}
                onSelect={selectEndpoint}
              />
              <div className="flex flex-col gap-3">
                <EndpointFleetGrid
                  endpoints={run.endpoints}
                  states={currentStates}
                  selectedId={selectedEndpointId ?? ""}
                  onSelect={selectEndpoint}
                />
                {selectedEndpointId && selectedState && (
                  <div className="rounded-xl border border-gray-200 bg-white p-4">
                    <div className="text-sm font-bold text-gray-900">{selectedEndpointId}</div>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                      <KV k="Risk" v={`${selectedState.risk.score}/100`} />
                      <KV k="Status" v={selectedState.risk.level.toUpperCase()} />
                    </div>
                    <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
                      Current evidence
                    </div>
                    <ul className="mt-1 space-y-1 text-xs">
                      {evidence.map((i) => (
                        <li key={i.key} className="flex items-center gap-2">
                          <TbCheck
                            className={clsx(
                              "h-3.5 w-3.5 shrink-0",
                              i.observed ? "text-emerald-500" : "text-gray-300"
                            )}
                          />
                          <span className={i.observed ? "text-gray-700" : "text-gray-400 line-through"}>
                            {i.title}
                          </span>
                        </li>
                      ))}
                    </ul>
                    <Link
                      href="/incidents"
                      className="mt-3 inline-block rounded-lg bg-gray-900 px-3 py-1.5 text-xs font-semibold text-white"
                    >
                      Open incident →
                    </Link>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </NeedsScenario>
    </div>
  );
}

function Tally({ n, label, tone }: { n: number; label: string; tone: "good" | "warn" | "bad" | "default" }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-3 text-center">
      <div
        className={clsx(
          "font-mono text-2xl font-bold tabular-nums",
          tone === "good" && "text-emerald-600",
          tone === "warn" && "text-amber-600",
          tone === "bad" && "text-red-600",
          tone === "default" && "text-gray-900"
        )}
      >
        {n}
      </div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-gray-500">{label}</div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="text-gray-400">{k}</div>
      <div className="font-mono font-semibold text-gray-800">{v}</div>
    </div>
  );
}
