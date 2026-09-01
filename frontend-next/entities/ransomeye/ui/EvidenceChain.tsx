"use client";

import { useMemo } from "react";
import clsx from "clsx";
import { TbCheck, TbMinus } from "react-icons/tb";
import type { EndpointState, Tick } from "../model/types";
import { buildEvidenceChain, deriveVerdict, type EvidenceItem } from "../lib/evidenceChain";
import { factorLabel } from "../lib/format";

const VERDICT_UI = {
  critical: {
    box: "border-red-400 bg-red-50 dark:bg-red-950/40 dark:border-red-800",
    text: "text-red-700 dark:text-red-300",
  },
  warning: {
    box: "border-amber-400 bg-amber-50 dark:bg-amber-950/40 dark:border-amber-800",
    text: "text-amber-800 dark:text-amber-300",
  },
  clear: {
    box: "border-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-800",
    text: "text-emerald-700 dark:text-emerald-300",
  },
} as const;

function EvidenceRow({ item, index }: { item: EvidenceItem; index: number | null }) {
  return (
    <li
      className={clsx(
        "rounded-lg border px-3 py-2.5",
        item.observed
          ? "border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900"
          : "border-dashed border-gray-200 bg-gray-50/60 dark:border-gray-800 dark:bg-gray-900/40"
      )}
    >
      <div className="flex items-start gap-2.5">
        <span
          className={clsx(
            "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold",
            item.observed
              ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300"
              : "bg-gray-100 text-gray-400 dark:bg-gray-800 dark:text-gray-500"
          )}
        >
          {item.observed ? index : <TbMinus className="h-3 w-3" />}
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span
              className={clsx(
                "text-sm font-semibold",
                item.observed ? "text-gray-900 dark:text-gray-100" : "text-gray-400 dark:text-gray-500"
              )}
            >
              {item.title}
            </span>
            {item.mitre && (
              <span
                className={clsx(
                  "rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                  item.observed
                    ? "bg-gray-900 text-white dark:bg-gray-100 dark:text-gray-900"
                    : "bg-gray-200 text-gray-500 dark:bg-gray-800 dark:text-gray-500"
                )}
                title={`MITRE ATT&CK — ${item.mitre.name}`}
              >
                {item.mitre.id}
              </span>
            )}
            <span className="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
              {factorLabel(item.category)}
            </span>
            {item.observed && item.firstSeen && (
              <span className="ml-auto shrink-0 font-mono text-[11px] tabular-nums text-gray-400">
                {new Date(item.firstSeen).toLocaleTimeString(undefined, {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })}
              </span>
            )}
          </div>

          {item.observed ? (
            <>
              <div className="mt-1 text-sm text-gray-800 dark:text-gray-200">{item.observation}</div>
              {item.detail.length > 0 && (
                <ul className="mt-1 space-y-0.5">
                  {item.detail.map((d, i) => (
                    <li
                      key={i}
                      className="break-all font-mono text-[11px] leading-relaxed text-gray-500 dark:text-gray-400"
                    >
                      {d}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-1 text-[11px] italic text-gray-500 dark:text-gray-400">{item.rationale}</div>
            </>
          ) : (
            <div className="mt-0.5 text-xs text-gray-400 dark:text-gray-500">not observed</div>
          )}
        </div>
      </div>
    </li>
  );
}

/**
 * "Why we know" — the behavioral evidence chain. Shows observed signals with
 * their real measured values and MITRE technique, and deliberately keeps
 * unobserved ransomware tradecraft visible: the absences are what justify a
 * not-ransomware verdict on merely-anomalous activity.
 */
export function EvidenceChain({
  ticks,
  endpointId,
  state,
}: {
  ticks: Tick[];
  endpointId: string;
  state: EndpointState | undefined;
}) {
  const items = useMemo(() => buildEvidenceChain(ticks, endpointId, state), [ticks, endpointId, state]);
  const peakScore = useMemo(
    () => ticks.reduce((max, t) => Math.max(max, t.endpoint_states[endpointId]?.risk.score ?? 0), 0),
    [ticks, endpointId]
  );
  const verdict = useMemo(
    () => deriveVerdict(items, peakScore, state?.risk.score ?? 0),
    [items, peakScore, state]
  );
  const ui = VERDICT_UI[verdict.tone];

  let observedIndex = 0;

  return (
    <div className="rounded-xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-gray-200 px-4 py-3 dark:border-gray-800">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-[0.12em] text-gray-900 dark:text-gray-100">
            Why We Know
          </h2>
          <p className="mt-0.5 text-xs text-gray-500">
            Behavioral evidence for {endpointId}, measured from raw telemetry — mapped to MITRE ATT&amp;CK.
          </p>
        </div>
        <span className="text-[11px] tabular-nums text-gray-400">
          {verdict.tradecraftObserved}/{verdict.tradecraftTotal} tradecraft signals observed
        </span>
      </div>

      <ul className="flex flex-col gap-1.5 p-3">
        {items.map((item) => {
          if (item.observed) observedIndex += 1;
          return <EvidenceRow key={item.key} item={item} index={item.observed ? observedIndex : null} />;
        })}
      </ul>

      <div className={clsx("m-3 mt-0 rounded-lg border px-4 py-3", ui.box)}>
        <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-gray-500">Correlated Verdict</div>
        <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className={clsx("text-xl font-bold tracking-tight", ui.text)}>{verdict.label}</span>
          <span className="text-sm tabular-nums text-gray-600 dark:text-gray-400">
            peak risk {verdict.peakScore}/100
            {verdict.score !== verdict.peakScore && ` (currently ${verdict.score})`}
          </span>
        </div>
        <p className="mt-1.5 text-xs text-gray-700 dark:text-gray-300">{verdict.reasoning}</p>

        {state && (
          <div className="mt-2.5 border-t border-black/10 pt-2 dark:border-white/10">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
              Weighted contribution to score
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {Object.entries(state.risk.weighted_contribution_pct).map(([k, pct]) => (
                <span key={k} className="text-[11px] tabular-nums text-gray-600 dark:text-gray-400">
                  {factorLabel(k)}: <strong>{pct}</strong>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
