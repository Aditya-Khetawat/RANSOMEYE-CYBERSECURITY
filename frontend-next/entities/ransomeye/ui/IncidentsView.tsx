"use client";

import Link from "next/link";
import clsx from "clsx";
import { TbFlask } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";
import { computeDetectionWindow } from "../lib/attackStages";
import { PageHead, NeedsScenario } from "./pageParts";

export function IncidentsView() {
  const { run, revealedTicks, activeAlerts, contained, selectEndpoint } = useScenario();

  // Incidents = early warnings that have fired in the revealed timeline.
  const incidents = activeAlerts;

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="Understand"
        title="Ransomware Incidents"
        sub="Confirmed and suspected ransomware activity — not raw alerts. Each is a behavioral verdict with an early-warning window and a containment path."
      />

      <Link
        href="/lab"
        className="flex items-center gap-3 rounded-xl border border-orange-300 bg-orange-50 px-4 py-2.5 text-sm text-orange-800 transition hover:bg-orange-100"
      >
        <TbFlask className="h-4 w-4 shrink-0" />
        Generate a fresh incident live in the Attack Lab →
      </Link>

      <NeedsScenario>
        {run && incidents.length === 0 && (
          <div className="rounded-xl border border-dashed border-gray-300 bg-white p-8 text-center text-sm text-gray-500">
            No ransomware incident in this scenario so far.{" "}
            {run.scenario === "SUSPICIOUS_ACTIVITY"
              ? "Suspicious activity is present, but no ransomware tradecraft crossed threshold — that is the correct outcome here."
              : run.scenario === "NORMAL_ACTIVITY"
                ? "Normal fleet activity — nothing to raise."
                : "Let the timeline play forward."}
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          {incidents.map((a) => {
            const dw = computeDetectionWindow(revealedTicks, a.endpoint_id, a);
            const isContained = contained;
            return (
              <div
                key={a.id}
                className={clsx(
                  "rounded-xl border-l-4 border border-gray-200 bg-white p-4",
                  a.severity === "critical" ? "border-l-red-500" : "border-l-amber-500"
                )}
              >
                <div className="flex items-center justify-between">
                  <span
                    className={clsx(
                      "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase",
                      isContained
                        ? "bg-emerald-100 text-emerald-700"
                        : a.severity === "critical"
                          ? "bg-red-100 text-red-700"
                          : "bg-amber-100 text-amber-700"
                    )}
                  >
                    {isContained ? "Contained" : a.severity}
                  </span>
                  <span className="font-mono text-[11px] text-gray-400">
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div className="mt-2 text-base font-bold text-gray-900">{a.endpoint_id}</div>
                <div className="text-sm text-gray-600">{a.title.replace(`on ${a.endpoint_id}`, "").trim() || "Ransomware staging"}</div>

                <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                  <KV k="Confidence" v={`${a.risk_score}%`} />
                  <KV
                    k="Early warning"
                    v={dw.leadSeconds == null ? "—" : `${dw.leadSeconds}s`}
                  />
                  <KV k="Primary" v={a.primary_signal} />
                </div>

                <p className="mt-2 text-xs text-gray-500">{a.recommended_action}</p>

                <div className="mt-3 flex gap-2">
                  <Link
                    href="/evidence"
                    onClick={() => selectEndpoint(a.endpoint_id)}
                    className="rounded-lg bg-gray-900 px-3 py-1.5 text-xs font-semibold text-white"
                  >
                    Investigate →
                  </Link>
                  <Link
                    href="/containment"
                    onClick={() => selectEndpoint(a.endpoint_id)}
                    className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600"
                  >
                    Containment
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      </NeedsScenario>
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
