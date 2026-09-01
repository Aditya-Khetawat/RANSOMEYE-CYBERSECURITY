"use client";

import { Badge, Button, Card, Text, Title } from "@tremor/react";
import { LuPause, LuPlay, LuRotateCcw } from "react-icons/lu";
import { TbActivity, TbAlertTriangle, TbBiohazard } from "react-icons/tb";
import clsx from "clsx";
import type { ScenarioName, ScenarioRun } from "../model/types";

type ScenarioDef = {
  key: ScenarioName;
  label: string;
  description: string;
  icon: typeof TbActivity;
  color: string;
};

const SCENARIOS: ScenarioDef[] = [
  {
    key: "NORMAL_ACTIVITY",
    label: "Normal Activity",
    description: "Ordinary fleet-wide baseline. No anomaly, no alert.",
    icon: TbActivity,
    color: "text-emerald-600 border-emerald-200 hover:border-emerald-400",
  },
  {
    key: "SUSPICIOUS_ACTIVITY",
    label: "Suspicious Activity",
    description: "One endpoint runs an odd script — anomalous, but not an attack.",
    icon: TbAlertTriangle,
    color: "text-amber-600 border-amber-200 hover:border-amber-400",
  },
  {
    key: "RANSOMWARE_ATTACK",
    label: "Ransomware Attack",
    description: "Full kill chain: macro -> shadow-copy deletion -> mass encryption -> C2 beacon.",
    icon: TbBiohazard,
    color: "text-red-600 border-red-200 hover:border-red-400",
  },
];

export function ScenarioControls({
  run,
  isLoadingScenario,
  onRunScenario,
  tickIndex,
  isPlaying,
  onTogglePlay,
  onRestart,
  onScrub,
}: {
  run: ScenarioRun | undefined;
  isLoadingScenario: boolean;
  onRunScenario: (scenario: ScenarioName) => void;
  tickIndex: number;
  isPlaying: boolean;
  onTogglePlay: () => void;
  onRestart: () => void;
  onScrub: (tick: number) => void;
}) {
  const maxTick = (run?.ticks.length ?? 1) - 1;
  const currentTs = run?.ticks[tickIndex]?.ts;

  return (
    <Card className="p-4 flex flex-col gap-4">
      <div className="flex items-start justify-between flex-wrap gap-2">
        <div>
          <Title>Demo Mode</Title>
          <Text className="text-xs text-gray-500">
            Reproducible under a fixed seed — pick a scenario, the full telemetry timeline is precomputed and replayed below.
          </Text>
        </div>
        {run && (
          <Badge size="xs" color="gray">
            run {run.run_id} · {run.scenario.replace("_", " ")}
          </Badge>
        )}
      </div>

      <div className="grid sm:grid-cols-3 gap-2">
        {SCENARIOS.map((s) => {
          const Icon = s.icon;
          const active = run?.scenario === s.key;
          return (
            <button
              key={s.key}
              type="button"
              disabled={isLoadingScenario}
              onClick={() => onRunScenario(s.key)}
              className={clsx(
                "text-left rounded-lg border p-3 transition-colors disabled:opacity-50",
                s.color,
                active && "bg-gray-50 ring-1 ring-inset ring-current"
              )}
            >
              <div className="flex items-center gap-2 font-medium text-sm">
                <Icon className="w-4 h-4 shrink-0" />
                {s.label}
              </div>
              <div className="text-xs text-gray-500 mt-1">{s.description}</div>
            </button>
          );
        })}
      </div>

      {run && (
        <div className="border-t border-gray-200 pt-3 flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              icon={isPlaying ? LuPause : LuPlay}
              onClick={onTogglePlay}
            >
              {isPlaying ? "Pause" : "Play"}
            </Button>
            <Button size="xs" variant="secondary" icon={LuRotateCcw} onClick={onRestart}>
              Restart
            </Button>
            <input
              type="range"
              min={0}
              max={Math.max(maxTick, 0)}
              value={tickIndex}
              onChange={(e) => onScrub(Number(e.target.value))}
              className="flex-1 accent-red-500"
              aria-label="Timeline scrubber"
            />
            <Text className="text-xs text-gray-500 tabular-nums w-32 text-right">
              tick {tickIndex + 1}/{maxTick + 1}
              {currentTs ? ` · ${new Date(currentTs).toLocaleTimeString()}` : ""}
            </Text>
          </div>
        </div>
      )}
    </Card>
  );
}
