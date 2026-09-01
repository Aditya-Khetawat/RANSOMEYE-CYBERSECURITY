"use client";

import { Card, Text } from "@tremor/react";
import clsx from "clsx";
import type { Endpoint, EndpointState } from "../model/types";
import { riskColor } from "../lib/format";

/** Every endpoint in the fleet, coloured by its risk at the current tick —
 * the point is contrast: five endpoints staying flat/green while one climbs
 * is what proves the detector isn't just reacting to "any" activity. */
export function EndpointFleetGrid({
  endpoints,
  states,
  selectedId,
  onSelect,
}: {
  endpoints: Endpoint[];
  states: Record<string, EndpointState>;
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  return (
    <Card className="p-4">
      <Text className="text-xs text-gray-500 mb-3">Endpoint Fleet · Live Threat Feed source</Text>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {endpoints.map((ep) => {
          const risk = states[ep.id]?.risk;
          const color = risk ? riskColor(risk.level) : "gray";
          const selected = ep.id === selectedId;
          return (
            <button
              key={ep.id}
              type="button"
              onClick={() => onSelect(ep.id)}
              className={clsx(
                "text-left rounded-lg border p-2.5 transition-colors",
                selected ? "border-gray-900 ring-1 ring-gray-900" : "border-gray-200 hover:border-gray-400"
              )}
            >
              <div className="flex items-center justify-between gap-1">
                <span className="text-xs font-medium truncate">{ep.id}</span>
                <span
                  className={clsx("w-2 h-2 rounded-full shrink-0", {
                    "bg-emerald-500": color === "emerald",
                    "bg-amber-500": color === "amber",
                    "bg-red-500": color === "red",
                    "bg-rose-600": color === "rose",
                    "bg-gray-300": color === "gray",
                  })}
                />
              </div>
              <div className="text-[11px] text-gray-500 truncate">{ep.user} · {ep.department}</div>
              <div className="text-sm font-semibold tabular-nums mt-1">{risk?.score ?? 0}/100</div>
            </button>
          );
        })}
      </div>
    </Card>
  );
}
