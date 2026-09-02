"use client";

import { useCallback, useState } from "react";
import useSWR from "swr";
import { useApi } from "@/shared/lib/hooks/useApi";

/** Mirrors backend/app/ransomeye/lab/sandbox.py `LabSession.to_dict()`. */
export type LabProfile = "NORMAL" | "SUSPICIOUS" | "RANSOMWARE";
export type LabStatus = "idle" | "running" | "contained" | "completed";

export interface LabSignal {
  key: string;
  label: string;
  status: "ok" | "warning" | "critical";
  value: string;
  detail: string;
}

export interface LabDetection {
  detected: true;
  tick: number;
  sim_ts: string;
  confidence: number;
  lead_seconds: number | null;
  primary_signal: string | null;
}

export interface LabContainment {
  contained: true;
  tick: number;
  sim_ts: string;
  files_touched_at_containment: number;
  files_protected: number;
  endpoint_status: string;
  actions: { label: string; detail: string; done: boolean }[];
}

export interface LabCounterfactual {
  profile: LabProfile;
  total_files: number;
  files_encrypted: number;
  pct_encrypted: number;
  ticks_to_full: number;
  sim_seconds_to_full: number;
  catastrophe_tick: number | null;
  sim_seconds_to_catastrophe: number | null;
  peak_risk: number;
  endpoint_status: string;
}

export interface LabState {
  status: LabStatus;
  profile?: LabProfile;
  seed?: number;
  sim_tick_seconds?: number;
  tick?: number;
  sim_clock?: string;
  endpoint?: { id: string; hostname: string; user: string; department: string; ip: string };
  attacker?: { image: string; pid: number; state: string; profile: LabProfile };
  corpus?: { total: number; encrypted: number; remaining: number; pct_encrypted: number };
  files_touched?: number;
  rates?: Record<string, number>;
  risk?: {
    score: number;
    level: "low" | "medium" | "high" | "critical";
    factors: Record<string, number>;
    weighted_contribution_pct: Record<string, number>;
    ml_anomaly_score: number | null;
  };
  signals?: LabSignal[];
  evidence?: string[];
  detection?: LabDetection | null;
  containment?: LabContainment | null;
  forensic?: Record<string, unknown> | null;
  timeline?: { sim_ts: string; label: string; kind: string }[];
  counterfactual?: LabCounterfactual | null;
  catastrophe_pct?: number;
}

const LAB_KEY = "/ransomeye/lab";

/** Polls the live session. Fast while it's running, idle otherwise. */
export const useAttackLab = () => {
  const api = useApi();
  return useSWR<LabState>(
    api.isReady() ? LAB_KEY : null,
    (url: string) => api.get(url),
    {
      refreshInterval: (data) => (data?.status === "running" ? 500 : 0),
      revalidateOnFocus: false,
      dedupingInterval: 200,
    }
  );
};

export const useAttackLabControls = () => {
  const api = useApi();
  const { mutate } = useAttackLab();
  const [busy, setBusy] = useState(false);

  const run = useCallback(
    async (fn: () => Promise<LabState>) => {
      setBusy(true);
      try {
        const next = await fn();
        await mutate(next, { revalidate: false });
        return next;
      } finally {
        setBusy(false);
      }
    },
    [mutate]
  );

  return {
    busy,
    start: (profile: LabProfile, seed = 7) =>
      run(() => api.post<LabState>(`/ransomeye/lab/start?profile=${profile}&seed=${seed}`)),
    contain: () => run(() => api.post<LabState>("/ransomeye/lab/contain")),
    reset: () => run(() => api.post<LabState>("/ransomeye/lab/reset")),
  };
};
