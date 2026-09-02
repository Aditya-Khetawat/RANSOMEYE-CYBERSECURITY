import type { LabProfile, LabState } from "./useAttackLab";
import type { useScenario } from "./ScenarioContext";

export interface TourRunCtx {
  scenario: ReturnType<typeof useScenario>;
  lab: LabState | undefined;
  startLab: (p: LabProfile) => Promise<unknown>;
  containLab: () => Promise<unknown>;
}

export interface TourStep {
  id: string;
  path: string;
  /** `data-tour="…"` value of the element to spotlight; omit for a centred card. */
  spotlight?: string;
  eyebrow: string;
  title: string;
  body: string;
  /** optional one-line action hint shown under the body */
  hint?: string;
  /** stage the app for this step (load scenario, jump tick, start lab, …) */
  run?: (ctx: TourRunCtx) => void | Promise<void>;
}

const RANSOMWARE = "RANSOMWARE_ATTACK" as const;
const SUSPICIOUS = "SUSPICIOUS_ACTIVITY" as const;

export const TOUR_STEPS: TourStep[] = [
  {
    id: "intro",
    path: "/",
    spotlight: "command-center",
    eyebrow: "Judge Mode · 1 / 9",
    title: "Ransomware becomes a disaster when defenders react too late",
    body:
      "RansomEye watches the behavioural kill chain forming on an endpoint and raises a warning while there is still time to act. This is one real, seeded scenario replaying its telemetry — FINANCE-WS-042, mid-attack. Initial access and recovery inhibition have happened; mass encryption has not.",
    hint: "The kill chain below is derived from the raw events — nothing here is scripted.",
    run: async ({ scenario }) => {
      scenario.resetContained();
      await scenario.jumpTo({ scenario: RANSOMWARE, tick: 7 });
    },
  },
  {
    id: "detection",
    path: "/detection",
    spotlight: "detection-verdict",
    eyebrow: "See · 2 / 9",
    title: "Five independent signals, converging",
    body:
      "File behaviour, entropy, recovery inhibition, process tradecraft and network activity each move the risk score — and each contribution is shown. The verdict is driven by how many of these corroborate, not by a single number. It is an auditable weighted score, not a black box.",
    run: async ({ scenario }) => {
      await scenario.jumpTo({ scenario: RANSOMWARE, tick: 15 });
    },
  },
  {
    id: "false-positive",
    path: "/detection",
    spotlight: "detection-verdict",
    eyebrow: "See · 3 / 9",
    title: "The same detector does not cry wolf",
    body:
      "Now a noisy backup job on the same fleet: heavy file churn, an unsigned helper process — genuinely anomalous. But no recovery inhibition, no entropy flip, no known-bad contact. Verdict: not ransomware. Suppressing the alert you should not raise is the hard part.",
    run: async ({ scenario }) => {
      await scenario.jumpTo({ scenario: SUSPICIOUS, tick: 8 });
    },
  },
  {
    id: "evidence",
    path: "/evidence",
    spotlight: "evidence-chain",
    eyebrow: "Understand · 4 / 9",
    title: "Every verdict, backed by observable evidence",
    body:
      "Back to the attack, further along. Each behaviour is mapped to a MITRE ATT&CK technique, timestamped, and weighted. The chain shows the absences too — which is exactly what keeps the not-ransomware verdict honest.",
    run: async ({ scenario }) => {
      await scenario.jumpTo({ scenario: RANSOMWARE, tick: 16 });
    },
  },
  {
    id: "blast-radius",
    path: "/blast-radius",
    spotlight: "blast-horizons",
    eyebrow: "Predict · 5 / 9",
    title: "How far it gets if no one acts",
    body:
      "A deterministic projection of this endpoint's own file trajectory from the measured rate trend — +5, +10, +15 minutes — with the containment comparison beside it. Labelled as an estimate: we do not invent lateral-spread numbers we cannot measure.",
    run: async ({ scenario }) => {
      await scenario.jumpTo({ scenario: RANSOMWARE, tick: 14 });
    },
  },
  {
    id: "containment",
    path: "/containment",
    spotlight: "containment-actions",
    eyebrow: "Stop · 6 / 9",
    title: "One click, forensics preserved",
    body:
      "Suspend the process, isolate the endpoint from the domain, snapshot volatile evidence, notify the SOC. Destructive actions are approval-gated; the non-destructive ones auto-execute. Approving isolation here severs the endpoint on the fleet map for real.",
    hint: "The tour just approved containment — watch the posture flip across the app.",
    run: async ({ scenario }) => {
      await scenario.jumpTo({ scenario: RANSOMWARE, tick: 16 });
      scenario.markContained();
    },
  },
  {
    id: "lab-live",
    path: "/lab",
    spotlight: "lab-live",
    eyebrow: "Prove · 7 / 9",
    title: "Don't take the dashboard's word for it",
    body:
      "This is a controlled attack running right now against a synthetic 50,000-file endpoint — a benign simulator, never touching a real disk. Every operation is scored live by the same detection pipeline you just saw. It is already detected. Hit Contain, or press Next.",
    hint: "Contain suspends the simulator for real — the counters freeze where you stop it.",
    run: async ({ lab, startLab }) => {
      if (lab?.status !== "running" && lab?.status !== "contained") {
        await startLab("RANSOMWARE");
      }
    },
  },
  {
    id: "lab-outcome",
    path: "/lab",
    spotlight: "lab-outcome",
    eyebrow: "Prove · 8 / 9",
    title: "Same attack. Different outcome.",
    body:
      "Detected during staging, before mass encryption — a real advantage window, measured against a full replay of the same seed with no intervention. The files touched before containment versus the tens of thousands never encrypted is the whole product in two numbers.",
    run: async ({ lab, containLab }) => {
      if (lab && lab.status === "running" && !lab.containment) {
        await containLab();
      }
    },
  },
  {
    id: "evaluation",
    path: "/evaluation",
    spotlight: "eval-metrics",
    eyebrow: "Prove · 9 / 9",
    title: "And it is measured",
    body:
      "Precision, recall and F1 across 24 seeds and every scenario — reproducible, recomputed on the server, not asserted. Including the honest part: for the fastest smash-and-grab attacks the early-warning window shrinks toward zero. Detection holds; the head start does not.",
    hint: "SEE the attack forming · PROVE it under a live attack · UNDERSTAND the evidence · PREDICT the blast radius · STOP it. That is RansomEye.",
  },
];
