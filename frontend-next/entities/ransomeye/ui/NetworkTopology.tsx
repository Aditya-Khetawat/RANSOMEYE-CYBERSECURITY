"use client";

import { useMemo } from "react";
import clsx from "clsx";
import type { EarlyWarningAlert, Endpoint, EndpointState } from "../model/types";

const RISK_HEX: Record<string, string> = {
  emerald: "#10b981",
  amber: "#f59e0b",
  red: "#ef4444",
  rose: "#e11d48",
  gray: "#9ca3af",
};

function colorFor(level: string | undefined): string {
  switch (level) {
    case "critical":
      return RISK_HEX.rose;
    case "high":
      return RISK_HEX.red;
    case "medium":
      return RISK_HEX.amber;
    case "low":
      return RISK_HEX.emerald;
    default:
      return RISK_HEX.gray;
  }
}

const WIDTH = 640;
const HEIGHT = 320;
const DOMAIN_X = WIDTH / 2;
const DOMAIN_Y = 46;
const NODE_Y = 240;
const NODE_R = 26;

/**
 * Honest network topology, not a predictive blast-radius map: the backend's
 * forecast (see forecast.py) only projects risk and file impact forward on
 * the SAME endpoint over time — it does not model lateral spread to other
 * machines, and this component does not invent numbers for that. What it
 * shows instead is real: every endpoint's actual current risk state, and a
 * genuine before/after when an isolate-endpoint containment action is
 * approved (the connection to the domain is actually severed in the plan
 * this UI drives, not simulated for effect).
 */
export function NetworkTopology({
  endpoints,
  states,
  alert,
  contained,
  selectedEndpointId,
  onSelect,
}: {
  endpoints: Endpoint[];
  states: Record<string, EndpointState>;
  alert: EarlyWarningAlert | undefined;
  contained: boolean;
  selectedEndpointId: string | null;
  onSelect: (id: string) => void;
}) {
  const positions = useMemo(() => {
    const n = endpoints.length;
    const marginX = 70;
    const span = WIDTH - marginX * 2;
    return endpoints.map((ep, i) => ({
      ep,
      x: n === 1 ? WIDTH / 2 : marginX + (span * i) / (n - 1),
      y: NODE_Y,
    }));
  }, [endpoints]);

  const isolatedId = contained ? alert?.endpoint_id : null;

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <div className="mb-1 flex items-baseline justify-between">
        <h2 className="text-sm font-bold uppercase tracking-[0.12em] text-gray-900">
          Network Topology
        </h2>
        <span className="text-[11px] text-gray-400">
          {isolatedId ? "1 endpoint isolated" : "all endpoints on-domain"}
        </span>
      </div>
      <p className="mb-2 text-xs text-gray-500">
        Real fleet state, not a spread prediction — click a node to inspect it below.
      </p>

      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" role="img" aria-label="Fleet network topology">
        {/* domain node */}
        <g>
          <rect
            x={DOMAIN_X - 58}
            y={DOMAIN_Y - 18}
            width={116}
            height={36}
            rx={8}
            className="fill-gray-800"
          />
          <text
            x={DOMAIN_X}
            y={DOMAIN_Y + 5}
            textAnchor="middle"
            className="fill-white text-[11px] font-bold uppercase tracking-wide"
          >
            CORP-DOMAIN
          </text>
        </g>

        {/* connectors */}
        {positions.map(({ ep, x, y }) => {
          const severed = ep.id === isolatedId;
          const midY = (DOMAIN_Y + y) / 2;
          return (
            <g key={`line-${ep.id}`}>
              <path
                d={`M ${DOMAIN_X} ${DOMAIN_Y + 18} C ${DOMAIN_X} ${midY}, ${x} ${midY}, ${x} ${y - NODE_R}`}
                fill="none"
                stroke={severed ? "#ef4444" : "#d1d5db"}
                strokeWidth={severed ? 2 : 1.5}
                strokeDasharray={severed ? "5 4" : undefined}
              />
              {severed && (
                <g transform={`translate(${(DOMAIN_X + x) / 2}, ${midY})`}>
                  <circle r={11} fill="#fef2f2" stroke="#ef4444" strokeWidth={1.5} />
                  <text textAnchor="middle" dominantBaseline="central" className="fill-red-600 text-[12px] font-bold">
                    ✕
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* endpoint nodes */}
        {positions.map(({ ep, x, y }) => {
          const risk = states[ep.id]?.risk;
          const isAlert = alert?.endpoint_id === ep.id;
          const isSelected = ep.id === selectedEndpointId;
          const c = colorFor(risk?.level);
          const severed = ep.id === isolatedId;
          return (
            <g
              key={ep.id}
              transform={`translate(${x}, ${y})`}
              className="cursor-pointer"
              onClick={() => onSelect(ep.id)}
            >
              {isAlert && !severed && (
                <circle r={NODE_R + 8} fill="none" stroke={c} strokeWidth={2} opacity={0.5}>
                  <animate attributeName="r" values={`${NODE_R + 4};${NODE_R + 12};${NODE_R + 4}`} dur="1.6s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.6;0;0.6" dur="1.6s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                r={NODE_R}
                fill={severed ? "#e5e7eb" : c}
                fillOpacity={severed ? 1 : 0.15}
                stroke={severed ? "#9ca3af" : c}
                strokeWidth={isSelected ? 3 : 2}
              />
              <text textAnchor="middle" dominantBaseline="central" dy={-2} className="fill-gray-800 text-[15px]">
                {severed ? "🔒" : isAlert ? "⚠" : "🖥"}
              </text>
              <text
                textAnchor="middle"
                y={NODE_R + 14}
                className="fill-gray-700 text-[10px] font-semibold"
              >
                {ep.id}
              </text>
              <text textAnchor="middle" y={NODE_R + 26} className="fill-gray-400 text-[9px]">
                {ep.department}
              </text>
              <text
                textAnchor="middle"
                y={NODE_R + 38}
                className="fill-gray-500 text-[9px] tabular-nums"
              >
                {severed ? "ISOLATED" : `${risk?.score ?? 0}/100`}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
