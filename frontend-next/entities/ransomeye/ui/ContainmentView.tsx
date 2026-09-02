"use client";

import { useState } from "react";
import clsx from "clsx";
import { TbShieldLock } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";
import { PageHead, NeedsScenario, NeedsEndpoint } from "./pageParts";
import { ContainmentPanel } from "./ContainmentPanel";
import { CopilotPanel } from "./CopilotPanel";

type PolicyMode = "alert" | "approval" | "autonomous";

const PLAYBOOKS = [
  {
    title: "Ransomware Early Containment",
    trigger: "Ransomware confidence ≥ threshold AND ≥ 3 independent tradecraft signals",
    steps: [
      "Capture forensic state (process list, open handles)",
      "Suspend the flagged process tree",
      "Isolate the endpoint from the domain",
      "Block the known-bad network indicators",
      "Notify SOC on-call",
      "Generate the incident report",
    ],
  },
  {
    title: "Suspected Ransomware",
    trigger: "Elevated risk with incomplete corroboration",
    steps: [
      "Increase telemetry sampling on the endpoint",
      "Keep monitoring — do not isolate yet",
      "Preserve volatile evidence",
      "Request analyst approval to escalate",
    ],
  },
  {
    title: "Recovery Protection",
    trigger: "Shadow-copy deletion / recovery-disabling observed",
    steps: [
      "Preserve current disk + snapshot state immediately",
      "Escalate incident severity",
      "Check other endpoints for the same tradecraft",
      "Stage containment for one-click approval",
    ],
  },
];

export function ContainmentView() {
  const { selectedEndpointId, markContained } = useScenario();
  const [mode, setMode] = useState<PolicyMode>("approval");

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="Stop"
        title="Containment"
        sub="Stop ransomware propagation while preserving forensic context. Destructive actions are approval-gated; non-destructive ones auto-execute."
      />

      <NeedsScenario>
        <NeedsEndpoint>
          {selectedEndpointId && (
            <div data-tour="containment-actions" className="grid gap-4 lg:grid-cols-2 items-start">
              <ContainmentPanel endpointId={selectedEndpointId} onContainmentApproved={markContained} />
              <CopilotPanel endpointId={selectedEndpointId} />
            </div>
          )}
        </NeedsEndpoint>
      </NeedsScenario>

      {/* response policy */}
      <div className="rounded-xl border border-gray-200 bg-white p-4">
        <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">Response mode</div>
        <div className="flex flex-wrap gap-2">
          {(
            [
              ["alert", "Alert only"],
              ["approval", "Human approval"],
              ["autonomous", "Autonomous"],
            ] as [PolicyMode, string][]
          ).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setMode(k)}
              className={clsx(
                "rounded-lg border px-3 py-1.5 text-xs font-medium transition",
                mode === k
                  ? "border-gray-900 bg-gray-900 text-white"
                  : "border-gray-200 text-gray-600 hover:bg-gray-50"
              )}
            >
              {label}
            </button>
          ))}
        </div>
        {mode === "autonomous" && (
          <div className="mt-3 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">
            <TbShieldLock className="mr-1.5 inline h-3.5 w-3.5" />
            Autonomous containment would require: ransomware confidence &gt; 90% <em>and</em> ≥ 3 independent
            behavioral signals, <em>or</em> a high-confidence recovery-inhibition tripwire. This build always
            keeps a human in the loop for destructive actions — the mode selector is illustrative.
          </div>
        )}
      </div>

      {/* ransomware playbooks */}
      <div>
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          Response playbooks — ransomware-specific
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {PLAYBOOKS.map((p) => (
            <div key={p.title} className="rounded-xl border border-gray-200 bg-white p-4">
              <div className="text-sm font-bold text-gray-900">{p.title}</div>
              <div className="mt-1 text-[11px] text-gray-400">
                <span className="font-semibold uppercase tracking-wide">Trigger</span> · {p.trigger}
              </div>
              <ol className="mt-2 list-decimal space-y-1 pl-4 text-xs text-gray-600">
                {p.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
