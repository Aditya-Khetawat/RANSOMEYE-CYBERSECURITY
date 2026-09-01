"use client";

import { Badge, Button, Text, Title } from "@tremor/react";
import { TbAlertOctagon } from "react-icons/tb";
import type { EarlyWarningAlert } from "../model/types";

/** The Early Warning itself — fires once an endpoint crosses the risk
 * threshold. Deliberately loud (unlike the low-key StatCards elsewhere):
 * this is the moment the whole system exists to produce. */
export function AlertBanner({
  alert,
  onInvestigate,
}: {
  alert: EarlyWarningAlert;
  onInvestigate?: () => void;
}) {
  const critical = alert.severity === "critical";
  return (
    <div
      className={
        "rounded-lg border-2 p-4 flex flex-col gap-2 animate-[pulse_2s_ease-in-out_1]" +
        (critical ? " border-rose-500 bg-rose-50" : " border-red-400 bg-red-50")
      }
      role="alert"
    >
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-start gap-2 min-w-0">
          <TbAlertOctagon className={"w-6 h-6 shrink-0 mt-0.5 " + (critical ? "text-rose-600" : "text-red-500")} />
          <div className="min-w-0">
            <Title className={critical ? "text-rose-700" : "text-red-700"}>{alert.title}</Title>
            <Text className="text-sm text-gray-700">
              {alert.hostname} · user {alert.user} · risk {alert.risk_score}/100
            </Text>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge size="sm" color={critical ? "rose" : "red"}>
            {alert.severity.toUpperCase()}
          </Badge>
          {onInvestigate && (
            <Button size="xs" color={critical ? "rose" : "red"} onClick={onInvestigate}>
              Investigate
            </Button>
          )}
        </div>
      </div>

      <ul className="text-sm text-gray-800 list-disc pl-5 space-y-0.5">
        {alert.contributing_behaviors.slice(0, 4).map((b, i) => (
          <li key={i}>{b}</li>
        ))}
      </ul>

      <Text className="text-sm font-medium text-gray-800">
        Recommended: {alert.recommended_action}
      </Text>
    </div>
  );
}
