"use client";

import { Badge, Card, ProgressBar, Text, Title } from "@tremor/react";
import type { Risk } from "../model/types";
import { FACTOR_WEIGHT_MAX, factorLabel, riskColor } from "../lib/format";

/** The 0-100 risk score plus its weighted factor breakdown — every bar here
 * sums (weighted) to the headline score, so nothing on this card is a
 * number without a visible, inspectable source (see risk_engine.py). */
export function RiskGauge({ endpointId, risk }: { endpointId: string; risk: Risk }) {
  const color = riskColor(risk.level);
  return (
    <Card className="p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between">
        <div>
          <Text className="text-xs text-gray-500">Ransomware Risk Score</Text>
          <Title className="text-3xl tabular-nums">{risk.score}<span className="text-base text-gray-400">/100</span></Title>
        </div>
        <Badge size="lg" color={color}>{risk.level.toUpperCase()}</Badge>
      </div>

      <div className="flex flex-col gap-2">
        {Object.entries(risk.weighted_contribution_pct).map(([key, pct]) => (
          <div key={key}>
            <div className="flex justify-between text-xs text-gray-500 mb-0.5">
              <span>{factorLabel(key)}</span>
              <span>{pct}% of score</span>
            </div>
            <ProgressBar value={(pct / (FACTOR_WEIGHT_MAX[key] ?? 100)) * 100} color={color} className="h-1.5" />
          </div>
        ))}
      </div>

      {risk.ml_anomaly_score != null && (
        <Text className="text-xs text-gray-500 border-t border-gray-200 pt-2">
          Corroborating ML anomaly score (IsolationForest, not part of the score above): {Math.round(risk.ml_anomaly_score * 100)}%
        </Text>
      )}

      {risk.evidence.length > 0 && (
        <div className="border-t border-gray-200 pt-2">
          <Text className="text-xs text-gray-500 mb-1">Evidence · {endpointId}</Text>
          <ul className="text-xs text-gray-700 space-y-0.5 list-disc pl-4">
            {risk.evidence.slice(0, 3).map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
