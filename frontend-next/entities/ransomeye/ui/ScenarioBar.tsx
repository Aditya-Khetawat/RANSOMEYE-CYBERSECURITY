"use client";

import { usePathname } from "next/navigation";
import clsx from "clsx";
import { LuPause, LuPlay, LuRotateCcw } from "react-icons/lu";
import { TbActivity, TbAlertTriangle, TbBiohazard } from "react-icons/tb";
import type { ScenarioName } from "../model/types";
import { useScenario } from "../model/ScenarioContext";

const SCENARIOS: { key: ScenarioName; label: string; Icon: typeof TbActivity; tone: string }[] = [
  { key: "NORMAL_ACTIVITY", label: "Normal", Icon: TbActivity, tone: "emerald" },
  { key: "SUSPICIOUS_ACTIVITY", label: "Suspicious", Icon: TbAlertTriangle, tone: "amber" },
  { key: "RANSOMWARE_ATTACK", label: "Ransomware", Icon: TbBiohazard, tone: "red" },
];

const CHIP_TONE: Record<string, { on: string; off: string }> = {
  emerald: {
    on: "bg-emerald-600 text-white border-emerald-600",
    off: "border-emerald-300 text-emerald-700 hover:bg-emerald-50",
  },
  amber: {
    on: "bg-amber-500 text-white border-amber-500",
    off: "border-amber-300 text-amber-700 hover:bg-amber-50",
  },
  red: {
    on: "bg-red-600 text-white border-red-600",
    off: "border-red-300 text-red-700 hover:bg-red-50",
  },
};

// Pages that own their own state and should not show the scenario replay bar.
const HIDDEN_ON = ["/lab", "/evaluation", "/signin", "/mobile", "/error"];

export function ScenarioBar() {
  const pathname = usePathname();
  const {
    run,
    isLoadingScenario,
    loadScenario,
    tickIndex,
    isPlaying,
    togglePlay,
    restart,
    scrub,
  } = useScenario();

  if (HIDDEN_ON.some((p) => pathname === p || pathname.startsWith(p + "/"))) return null;

  const maxTick = (run?.ticks.length ?? 1) - 1;
  const ts = run?.ticks[tickIndex]?.ts;

  return (
    <div className="sticky top-0 z-20 -mx-4 mb-4 border-b border-gray-200 bg-gray-50/95 px-4 py-2.5 backdrop-blur">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-400">
          Scenario
        </span>
        <div className="flex gap-1.5">
          {SCENARIOS.map(({ key, label, Icon, tone }) => {
            const active = run?.scenario === key;
            const t = CHIP_TONE[tone];
            return (
              <button
                key={key}
                type="button"
                disabled={isLoadingScenario}
                onClick={() => loadScenario(key)}
                className={clsx(
                  "flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition disabled:opacity-50",
                  active ? t.on : t.off
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            );
          })}
        </div>

        {run && (
          <div className="flex min-w-[220px] flex-1 items-center gap-2">
            <button
              onClick={togglePlay}
              className="rounded-md border border-gray-300 p-1 text-gray-600 hover:bg-white"
              aria-label={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? <LuPause className="h-3.5 w-3.5" /> : <LuPlay className="h-3.5 w-3.5" />}
            </button>
            <button
              onClick={restart}
              className="rounded-md border border-gray-300 p-1 text-gray-600 hover:bg-white"
              aria-label="Restart"
            >
              <LuRotateCcw className="h-3.5 w-3.5" />
            </button>
            <input
              type="range"
              min={0}
              max={Math.max(maxTick, 0)}
              value={tickIndex}
              onChange={(e) => scrub(Number(e.target.value))}
              className="h-1 flex-1 accent-red-500"
              aria-label="Timeline scrubber"
            />
            <span className="w-28 text-right text-[11px] tabular-nums text-gray-400">
              t{tickIndex + 1}/{maxTick + 1}
              {ts ? ` · ${new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}` : ""}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
