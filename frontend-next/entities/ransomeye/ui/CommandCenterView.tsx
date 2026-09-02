"use client";

import Link from "next/link";
import { TbArrowRight, TbFlask } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";
import { PageHead, NeedsScenario } from "./pageParts";
import { CommandCenter } from "./CommandCenter";
import { AlertBanner } from "./AlertBanner";
import { EndpointFleetGrid } from "./EndpointFleetGrid";
import { ThreatFeed } from "./ThreatFeed";

export function CommandCenterView() {
  const {
    run,
    revealedTicks,
    currentStates,
    activeAlerts,
    contained,
    selectedEndpointId,
    selectEndpoint,
  } = useScenario();

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="Behavior → Early Warning → Containment"
        title="RansomEye Command Center"
        sub="Real-time ransomware early warning across the endpoint fleet — the behavioral progression, the current posture, and how much warning time it bought."
      />

      <Link
        href="/lab"
        className="group flex items-center justify-between gap-3 rounded-xl border border-orange-300 bg-orange-50 px-4 py-3 transition hover:border-orange-400 hover:bg-orange-100"
      >
        <span className="flex items-center gap-3">
          <TbFlask className="h-5 w-5 shrink-0 text-orange-600" />
          <span>
            <span className="block text-sm font-semibold text-orange-900">
              Prove it — launch a live attack in the Attack Lab
            </span>
            <span className="block text-xs text-orange-700/80">
              Run a controlled ransomware attack against a synthetic endpoint and watch RansomEye stop
              it before mass encryption.
            </span>
          </span>
        </span>
        <TbArrowRight className="h-5 w-5 shrink-0 text-orange-600 transition group-hover:translate-x-0.5" />
      </Link>

      <NeedsScenario>
        {run && (
          <>
            <CommandCenter
              endpoints={run.endpoints}
              states={currentStates}
              ticks={revealedTicks}
              alert={activeAlerts[0]}
              contained={contained}
              targetEndpointId={run.target_endpoint_id}
            />

            {activeAlerts.map((alert) => (
              <AlertBanner
                key={alert.id}
                alert={alert}
                onInvestigate={() => selectEndpoint(alert.endpoint_id)}
              />
            ))}

            <div className="grid gap-4 lg:grid-cols-2 items-start">
              <div className="flex flex-col gap-2">
                <EndpointFleetGrid
                  endpoints={run.endpoints}
                  states={currentStates}
                  selectedId={selectedEndpointId ?? ""}
                  onSelect={selectEndpoint}
                />
                <div className="flex flex-wrap gap-2 text-xs">
                  <Link href="/detection" className="rounded-lg border border-gray-200 px-3 py-1.5 font-medium text-gray-600 hover:bg-white">
                    Why RansomEye is concerned →
                  </Link>
                  <Link href="/evidence" className="rounded-lg border border-gray-200 px-3 py-1.5 font-medium text-gray-600 hover:bg-white">
                    See the evidence →
                  </Link>
                  <Link href="/containment" className="rounded-lg border border-gray-200 px-3 py-1.5 font-medium text-gray-600 hover:bg-white">
                    Containment →
                  </Link>
                </div>
              </div>
              <ThreatFeed ticks={revealedTicks} />
            </div>
          </>
        )}
      </NeedsScenario>
    </div>
  );
}
