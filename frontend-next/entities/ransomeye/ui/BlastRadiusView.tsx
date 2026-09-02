"use client";

import { useEffect, useState } from "react";
import clsx from "clsx";
import { useScenario } from "../model/ScenarioContext";
import { useEndpointForecast } from "../model/useRansomEye";
import type { EndpointForecast } from "../model/types";
import { PageHead, NeedsScenario, NeedsEndpoint } from "./pageParts";

export function BlastRadiusView() {
  const { selectedEndpointId, selectedState, tickIndex, contained } = useScenario();
  const { getForecast } = useEndpointForecast();
  const [fc, setFc] = useState<EndpointForecast | null>(null);

  useEffect(() => {
    setFc(null);
    if (!selectedEndpointId) return;
    let live = true;
    getForecast(selectedEndpointId, tickIndex).then((r) => live && setFc(r));
    return () => {
      live = false;
    };
  }, [selectedEndpointId, tickIndex, getForecast]);

  const nowFiles = selectedState?.feat.files_touched ?? 0;
  const worst = fc?.forecast[fc.forecast.length - 1];

  return (
    <div className="flex flex-col gap-4">
      <PageHead
        eyebrow="Predict"
        title="Blast Radius Forecast"
        sub="How far the encryption gets on this endpoint if containment does not occur — projected from the real risk and file-rate trend, not asserted."
      />

      <NeedsScenario>
        <NeedsEndpoint>
          {selectedEndpointId && (
            <>
              <div data-tour="blast-horizons" className="rounded-xl border border-gray-200 bg-white p-5">
                <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                  What happens next on {selectedEndpointId}
                </div>
                <div className="grid gap-3 sm:grid-cols-4">
                  <Horizon label="Now" risk={selectedState?.risk.score ?? 0} files={nowFiles} />
                  {(fc?.forecast ?? []).map((s) => (
                    <Horizon key={s.minutes} label={`+${s.minutes} min`} risk={s.risk} files={s.estimated_files_encrypted} />
                  ))}
                  {!fc && <div className="col-span-3 self-center text-xs text-gray-400">projecting…</div>}
                </div>
                {fc && (
                  <ul className="mt-3 border-t border-gray-100 pt-3 text-xs text-gray-500">
                    {fc.reasoning.map((r, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-gray-300">·</span>
                        {r}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {worst && (
                <div className="rounded-2xl border border-gray-200 bg-white p-5">
                  <div className="mb-4 text-center text-sm font-bold uppercase tracking-[0.16em] text-gray-900">
                    Containment impact
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-red-200 bg-red-50/50 p-4">
                      <div className="mb-2 text-xs font-bold uppercase text-red-700">
                        Without containment (+{worst.minutes}m)
                      </div>
                      <Row v={`~${worst.estimated_files_encrypted.toLocaleString()}`} k="files encrypted (projected)" />
                      <Row v={`${worst.risk}/100`} k="projected risk" />
                    </div>
                    <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4">
                      <div className="mb-2 text-xs font-bold uppercase text-emerald-700">
                        With RansomEye
                      </div>
                      <Row v={contained ? "frozen" : nowFiles.toLocaleString()} k={contained ? "encryption halted at containment" : "files touched so far"} />
                      <Row v={contained ? "ISOLATED" : "staged"} k="endpoint — containment ready" />
                    </div>
                  </div>
                  <p className="mt-3 text-center text-[11px] text-gray-400">
                    Simulated / estimated impact — a deterministic projection of this endpoint&apos;s own file
                    trajectory. Lateral spread to other hosts is not modelled.
                  </p>
                </div>
              )}
            </>
          )}
        </NeedsEndpoint>
      </NeedsScenario>
    </div>
  );
}

function Horizon({ label, risk, files }: { label: string; risk: number; files: number }) {
  return (
    <div className="rounded-xl border border-gray-200 p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">{label}</div>
      <div
        className={clsx(
          "mt-1 font-mono text-2xl font-bold tabular-nums",
          risk >= 60 ? "text-red-600" : risk >= 30 ? "text-amber-600" : "text-gray-900"
        )}
      >
        {risk}
      </div>
      <div className="text-[11px] text-gray-500">~{files.toLocaleString()} files</div>
    </div>
  );
}

function Row({ v, k }: { v: string; k: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-black/5 py-1 last:border-0">
      <span className="font-mono text-sm font-bold text-gray-900">{v}</span>
      <span className="text-right text-[11px] text-gray-500">{k}</span>
    </div>
  );
}
