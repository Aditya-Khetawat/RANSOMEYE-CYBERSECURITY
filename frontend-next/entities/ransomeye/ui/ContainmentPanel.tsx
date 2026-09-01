"use client";

import { useState } from "react";
import { Badge, Button, Card, Text, Title } from "@tremor/react";
import { TbLock, TbShieldCheck } from "react-icons/tb";
import type { ContainmentAction } from "../model/types";
import { useContainment } from "../model/useRansomEye";

/** Defensive containment recommendations. Non-destructive actions
 * (preserve telemetry, notify SOC) come back already "executed"; destructive
 * ones (suspend process, isolate endpoint, block indicator) come back
 * pending and only change state when an operator explicitly approves them
 * here — this prototype never executes them on its own. */
export function ContainmentPanel({ endpointId }: { endpointId: string }) {
  const { getPlan, approveAction, isLoading } = useContainment();
  const [actions, setActions] = useState<ContainmentAction[] | null>(null);
  const [approvingId, setApprovingId] = useState<string | null>(null);

  const load = async () => {
    const plan = await getPlan(endpointId);
    setActions(plan.actions);
  };

  const approve = async (actionId: string) => {
    setApprovingId(actionId);
    try {
      const updated = await approveAction(endpointId, actionId);
      setActions((prev) => prev?.map((a) => (a.id === updated.id ? updated : a)) ?? null);
    } finally {
      setApprovingId(null);
    }
  };

  return (
    <Card className="p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <Title className="text-sm">Containment Recommendations</Title>
        <Button size="xs" variant="secondary" loading={isLoading} onClick={load}>
          {actions ? "Refresh" : "Generate plan"}
        </Button>
      </div>

      {actions && (
        <div className="flex flex-col gap-2">
          {actions.map((a) => (
            <div key={a.id} className="rounded-lg border border-gray-200 p-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  {a.destructive ? <TbLock className="w-4 h-4 text-red-500 shrink-0" /> : <TbShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />}
                  <Text className="text-sm font-medium">{a.title}</Text>
                </div>
                <Text className="text-xs text-gray-500 mt-0.5">{a.description}</Text>
              </div>
              <div className="shrink-0">
                {a.status === "executed" ? (
                  <Badge size="xs" color="emerald">executed</Badge>
                ) : (
                  <Button
                    size="xs"
                    color="red"
                    loading={approvingId === a.id}
                    onClick={() => approve(a.id)}
                  >
                    Approve
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
