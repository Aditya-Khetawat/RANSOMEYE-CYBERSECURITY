"use client";

import { Badge, Card, Text, Title } from "@tremor/react";
import { TbLoader2 } from "react-icons/tb";
import { useRansomEyeEvaluation } from "../model/useRansomEye";
import type { PerScenarioEvaluation, ScenarioName } from "../model/types";

function Pct({ value }: { value: number | null }) {
  if (value === null) return <span className="text-gray-400">—</span>;
  return <span className="tabular-nums">{Math.round(value * 100)}%</span>;
}

function MetricTile({
  label,
  children,
  tone = "default",
}: {
  label: string;
  children: React.ReactNode;
  tone?: "default" | "good" | "bad";
}) {
  return (
    <Card className="p-4">
      <Text className="text-xs text-gray-500">{label}</Text>
      <div
        className={
          "mt-1 text-3xl font-bold tabular-nums " +
          (tone === "good" ? "text-emerald-600" : tone === "bad" ? "text-red-600" : "text-gray-900")
        }
      >
        {children}
      </div>
    </Card>
  );
}

const SCENARIO_LABEL: Record<ScenarioName, string> = {
  NORMAL_ACTIVITY: "Normal Activity",
  SUSPICIOUS_ACTIVITY: "Suspicious Activity",
  RANSOMWARE_ATTACK: "Ransomware Attack",
};

function ScenarioRow({ scenario, entry }: { scenario: ScenarioName; entry: PerScenarioEvaluation }) {
  const good = entry.expected_to_fire ? entry.fire_rate_pct === 100 : entry.fire_rate_pct === 0;
  return (
    <tr className="border-b border-gray-100 last:border-0">
      <td className="py-2 pr-4 font-medium">{SCENARIO_LABEL[scenario]}</td>
      <td className="py-2 pr-4 text-gray-500">{entry.expected_to_fire ? "should alert" : "should NOT alert"}</td>
      <td className="py-2 pr-4">
        <Badge size="xs" color={good ? "emerald" : "red"}>
          {entry.alerts_fired}/{entry.seeds_tested} fired
        </Badge>
      </td>
      <td className="py-2 pr-4 tabular-nums text-gray-600">
        {entry.min_peak_risk}–{entry.max_peak_risk}/100
      </td>
      <td className="py-2 tabular-nums text-gray-500">avg {entry.mean_peak_risk}/100</td>
    </tr>
  );
}

/**
 * "Can we trust it?" — every number here comes from actually running
 * demo.run_scenario for real across a fixed seed set (see
 * backend/app/ransomeye/evaluation.py) and reading whether the detector's
 * outcome matched the generator's own ground truth. Nothing is a constant.
 */
export function EvaluationDashboard() {
  const { data, isLoading, error } = useRansomEyeEvaluation();

  if (isLoading) {
    return (
      <Card className="p-8 flex flex-col items-center gap-2 text-center">
        <TbLoader2 className="w-6 h-6 animate-spin text-red-500" />
        <Text className="text-sm text-gray-500">
          Running every scenario across every seed for real — usually ~15-20s the first time, then cached.
        </Text>
      </Card>
    );
  }

  if (error || !data) {
    return (
      <Card className="p-6">
        <Text className="text-sm text-red-500">Could not load the evaluation. Is the backend running?</Text>
      </Card>
    );
  }

  const rw = data.per_scenario.RANSOMWARE_ATTACK;
  const lead = data.detection_lead_seconds;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <span className="text-[11px] font-semibold tracking-[0.14em] uppercase text-red-500">
          Prove
        </span>
        <h1 className="text-2xl font-bold tracking-tight text-gray-900 mt-1">
          Trust &amp; Evaluation
        </h1>
        <Text className="text-sm text-gray-500 mt-1 max-w-2xl">
          Reproducible evaluation of ransomware detection, false positives and early-warning performance.
          Every scenario is replayed at every seed for real — precision, recall and detection lead time are
          measured outcomes, not asserted numbers. We also measure <em>how early</em> detection fires, and
          where that warning window disappears.
        </Text>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricTile label="Precision" tone={data.precision === 1 ? "good" : "default"}>
          <Pct value={data.precision} />
        </MetricTile>
        <MetricTile label="Recall" tone={data.recall === 1 ? "good" : "default"}>
          <Pct value={data.recall} />
        </MetricTile>
        <MetricTile label="F1" tone={data.f1 === 1 ? "good" : "default"}>
          <Pct value={data.f1} />
        </MetricTile>
        <MetricTile label="False Positive Rate" tone={data.false_positive_rate === 0 ? "good" : "bad"}>
          <Pct value={data.false_positive_rate} />
        </MetricTile>
      </div>

      <Card className="p-4">
        <Title className="text-sm">Detection outcome by scenario</Title>
        <Text className="text-xs text-gray-500 mb-3">
          {data.seeds_tested.length} seeds tested per scenario ({data.seeds_tested.join(", ")}) — reproducible, not
          cherry-picked.
        </Text>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-gray-400 border-b border-gray-200">
                <th className="pb-2 pr-4 font-medium">Scenario</th>
                <th className="pb-2 pr-4 font-medium">Ground truth</th>
                <th className="pb-2 pr-4 font-medium">Outcome</th>
                <th className="pb-2 pr-4 font-medium">Peak risk range</th>
                <th className="pb-2 font-medium">Mean</th>
              </tr>
            </thead>
            <tbody>
              {(Object.keys(data.per_scenario) as ScenarioName[]).map((s) => (
                <ScenarioRow key={s} scenario={s} entry={data.per_scenario[s]} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {rw.full_kill_chain && rw.smash_and_grab && (
        <Card className="p-4">
          <Title className="text-sm">Detection by kill-chain completeness</Title>
          <Text className="text-xs text-gray-500 mb-3">
            Not every ransomware run in the seed set uses the full kill chain — roughly a third skip shadow-copy
            deletion and privilege escalation entirely (a faster, less careful attacker), to test whether detection
            still holds on mass-encryption and network signals alone.
          </Text>
          <div className="grid sm:grid-cols-2 gap-3">
            <div className="rounded-lg border border-gray-200 p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Full kill chain</div>
              <div className="text-xl font-bold tabular-nums mt-1">
                {rw.full_kill_chain.detection_rate_pct}%{" "}
                <span className="text-xs font-normal text-gray-400">
                  ({rw.full_kill_chain.alerts_fired}/{rw.full_kill_chain.seeds_tested})
                </span>
              </div>
              <div className="text-xs text-gray-500 mt-1">
                mean lead time: <strong>{rw.full_kill_chain.mean_lead_seconds}s</strong>
              </div>
            </div>
            <div className="rounded-lg border border-gray-200 p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Smash-and-grab (no defense evasion)
              </div>
              <div className="text-xl font-bold tabular-nums mt-1">
                {rw.smash_and_grab.detection_rate_pct}%{" "}
                <span className="text-xs font-normal text-gray-400">
                  ({rw.smash_and_grab.alerts_fired}/{rw.smash_and_grab.seeds_tested})
                </span>
              </div>
              <div className="text-xs text-gray-500 mt-1">
                mean lead time: <strong>{rw.smash_and_grab.mean_lead_seconds}s</strong>
              </div>
            </div>
          </div>
          <Text className="text-xs text-gray-500 mt-3 italic">
            Both variants are still detected, but a smash-and-grab attacker is caught with less advance warning on
            average — there are fewer independent behavioral signals ahead of the encryption itself when defense
            evasion is skipped. This is a real, disclosed tradeoff, not a claim of uniform performance.
          </Text>
        </Card>
      )}

      <Card className="p-4">
        <Title className="text-sm">Detection lead time (ransomware runs only)</Title>
        <Text className="text-xs text-gray-500 mb-2">
          Gap between the early warning firing and the tick where file activity actually peaked, across{" "}
          {lead.n} detected runs.
        </Text>
        <div className="flex gap-6 text-sm">
          <div>
            <div className="text-xs text-gray-500">Mean</div>
            <div className="text-lg font-bold tabular-nums">{lead.mean}s</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Min</div>
            <div className="text-lg font-bold tabular-nums">{lead.min}s</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Max</div>
            <div className="text-lg font-bold tabular-nums">{lead.max}s</div>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <Title className="text-sm">Confusion matrix</Title>
        <div className="grid grid-cols-2 gap-2 mt-2 max-w-sm text-center text-sm">
          <div className="rounded bg-emerald-50 p-3">
            <div className="text-xl font-bold text-emerald-700">{data.confusion_matrix.tp}</div>
            <div className="text-xs text-gray-500">True Positive</div>
          </div>
          <div className="rounded bg-gray-50 p-3">
            <div className="text-xl font-bold text-gray-700">{data.confusion_matrix.fn}</div>
            <div className="text-xs text-gray-500">False Negative</div>
          </div>
          <div className="rounded bg-gray-50 p-3">
            <div className="text-xl font-bold text-gray-700">{data.confusion_matrix.fp}</div>
            <div className="text-xs text-gray-500">False Positive</div>
          </div>
          <div className="rounded bg-emerald-50 p-3">
            <div className="text-xl font-bold text-emerald-700">{data.confusion_matrix.tn}</div>
            <div className="text-xs text-gray-500">True Negative</div>
          </div>
        </div>
      </Card>
    </div>
  );
}
