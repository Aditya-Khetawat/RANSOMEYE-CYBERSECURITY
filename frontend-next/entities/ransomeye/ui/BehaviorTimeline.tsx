"use client";

import { useMemo } from "react";
import { AreaChart, Card, Text, Title } from "@tremor/react";
import type { Tick } from "../model/types";

/** Risk score trajectory for the selected endpoint across every revealed
 * tick — the "behavioral analysis" view: a single glance shows exactly
 * where risk started climbing and why (the threshold line makes the alert
 * crossing point obvious without reading the number). */
export function BehaviorTimeline({
  ticks,
  endpointId,
  alertThreshold = 60,
}: {
  ticks: Tick[];
  endpointId: string;
  alertThreshold?: number;
}) {
  const data = useMemo(
    () =>
      ticks.map((t) => ({
        tick: `t${t.tick}`,
        "Risk Score": t.endpoint_states[endpointId]?.risk.score ?? 0,
        "Alert Threshold": alertThreshold,
      })),
    [ticks, endpointId, alertThreshold]
  );

  return (
    <Card className="p-4">
      <Title className="text-sm">Behavioral Timeline · {endpointId}</Title>
      <Text className="text-xs text-gray-500 mb-2">Risk score per 30s tick, this scenario run</Text>
      <AreaChart
        className="h-56 mt-2"
        data={data}
        index="tick"
        categories={["Risk Score", "Alert Threshold"]}
        colors={["red", "gray"]}
        showAnimation
        curveType="monotone"
        yAxisWidth={32}
        minValue={0}
        maxValue={100}
      />
    </Card>
  );
}
