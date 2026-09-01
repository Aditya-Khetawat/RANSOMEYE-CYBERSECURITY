"use client";

import { useState } from "react";
import { BarChart, Button, Card, Text, Title } from "@tremor/react";
import type { EndpointForecast } from "../model/types";
import { useEndpointForecast } from "../model/useRansomEye";

/** Encryption Impact Forecast — +5/+10/+15 minute projection, computed
 * on-demand from the endpoint's risk trend as of the currently-viewed tick
 * (see backend/app/ransomeye/forecast.py). */
export function ForecastPanel({ endpointId, atTick }: { endpointId: string; atTick: number }) {
  const { getForecast, isLoading } = useEndpointForecast();
  const [forecast, setForecast] = useState<EndpointForecast | null>(null);

  const run = async () => {
    const fc = await getForecast(endpointId, atTick);
    setForecast(fc);
  };

  return (
    <Card className="p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <Title className="text-sm">Encryption Impact Forecast</Title>
        <Button size="xs" variant="secondary" loading={isLoading} onClick={run}>
          {forecast ? "Refresh" : "Forecast +5/+10/+15m"}
        </Button>
      </div>

      {forecast && (
        <>
          <BarChart
            className="h-40"
            data={forecast.forecast.map((s) => ({ horizon: `+${s.minutes}m`, "Projected Risk": s.risk }))}
            index="horizon"
            categories={["Projected Risk"]}
            colors={["red"]}
            yAxisWidth={32}
            maxValue={100}
            showAnimation
          />
          <div className="grid grid-cols-3 gap-2 text-center text-xs">
            {forecast.forecast.map((s) => (
              <div key={s.minutes} className="rounded border border-gray-200 p-2">
                <div className="text-gray-500">+{s.minutes}m</div>
                <div className="font-semibold">{s.risk}/100</div>
                <div className="text-gray-500">~{s.estimated_files_encrypted} files</div>
              </div>
            ))}
          </div>
          <Text className="text-xs font-medium text-gray-800">{forecast.recommendedImmediateAction}</Text>
          <ul className="text-xs text-gray-600 list-disc pl-4 space-y-0.5">
            {forecast.reasoning.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}
