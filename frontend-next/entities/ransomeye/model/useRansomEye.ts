import { useCallback, useState } from "react";
import useSWR, { SWRConfiguration } from "swr";
import useSWRImmutable from "swr/immutable";
import { useApi } from "@/shared/lib/hooks/useApi";
import type {
  ContainmentAction,
  ContainmentPlan,
  CopilotMessage,
  CopilotResponse,
  EndpointForecast,
  EvaluationResult,
  ScenarioName,
  ScenarioRun,
} from "./types";

export const RANSOMEYE_STATE_KEY = "/ransomeye/state";

/** GET /ransomeye/state — the currently-loaded scenario run, if any. 404s
 * with nothing loaded yet, which SWR surfaces as `error` (not a crash). */
export const useRansomEyeState = (options: SWRConfiguration = {}) => {
  const api = useApi();
  return useSWR<ScenarioRun>(
    api.isReady() ? RANSOMEYE_STATE_KEY : null,
    (url: string) => api.get(url),
    { revalidateOnFocus: false, ...options }
  );
};

/** POST /ransomeye/demo/{scenario} — runs a fresh, fully-precomputed
 * scenario timeline and refreshes /ransomeye/state to match. Imperative
 * (not SWR) since this is a one-shot action, same shape as
 * usePipelineActions.loadDemo. */
export const useLoadScenario = () => {
  const api = useApi();
  const { mutate } = useRansomEyeState({ revalidateOnFocus: false });
  const [isLoading, setIsLoading] = useState(false);

  const loadScenario = useCallback(
    async (scenario: ScenarioName, seed?: number) => {
      setIsLoading(true);
      try {
        const qs = seed != null ? `?seed=${seed}` : "";
        const run = await api.post<ScenarioRun>(`/ransomeye/demo/${scenario}${qs}`);
        await mutate(run, { revalidate: false });
        return run;
      } finally {
        setIsLoading(false);
      }
    },
    [api, mutate]
  );

  return { loadScenario, isLoading };
};

/** GET /ransomeye/endpoints/{id}/forecast — imperative, called on demand
 * (not polled) so the analyst controls exactly which tick it forecasts from. */
export const useEndpointForecast = () => {
  const api = useApi();
  const [isLoading, setIsLoading] = useState(false);

  const getForecast = useCallback(
    async (endpointId: string, atTick?: number) => {
      setIsLoading(true);
      try {
        const qs = atTick != null ? `?at_tick=${atTick}` : "";
        return await api.get<EndpointForecast>(
          `/ransomeye/endpoints/${encodeURIComponent(endpointId)}/forecast${qs}`
        );
      } finally {
        setIsLoading(false);
      }
    },
    [api]
  );

  return { getForecast, isLoading };
};

/** GET/POST containment plan + per-action approval. The backend caches the
 * generated plan server-side per endpoint (so approving an action mutates
 * the same list on the next GET) — this hook just mirrors that locally so
 * the UI updates optimistically without a full refetch. */
export const useContainment = () => {
  const api = useApi();
  const [isLoading, setIsLoading] = useState(false);

  const getPlan = useCallback(
    async (endpointId: string) => {
      setIsLoading(true);
      try {
        return await api.get<ContainmentPlan>(
          `/ransomeye/endpoints/${encodeURIComponent(endpointId)}/containment`
        );
      } finally {
        setIsLoading(false);
      }
    },
    [api]
  );

  const approveAction = useCallback(
    async (endpointId: string, actionId: string) => {
      const res = await api.post<{ endpoint_id: string; action: ContainmentAction }>(
        `/ransomeye/endpoints/${encodeURIComponent(endpointId)}/containment/${encodeURIComponent(actionId)}/approve`
      );
      return res.action;
    },
    [api]
  );

  return { getPlan, approveAction, isLoading };
};

/** POST /ransomeye/copilot — imperative chat turn: not cacheable, so a
 * plain callback rather than an SWR hook. */
export const useRansomEyeCopilot = () => {
  const api = useApi();
  const [isAsking, setIsAsking] = useState(false);

  const ask = useCallback(
    async (endpointId: string, question: string, conversation: CopilotMessage[] = []) => {
      setIsAsking(true);
      try {
        return await api.post<CopilotResponse>("/ransomeye/copilot", {
          endpoint_id: endpointId,
          question,
          conversation,
        });
      } finally {
        setIsAsking(false);
      }
    },
    [api]
  );

  return { ask, isAsking };
};

/** GET /ransomeye/evaluation — real detection outcomes measured across a
 * fixed seed set (see backend/app/ransomeye/evaluation.py). Immutable and
 * not revalidated: the backend actually re-runs every scenario at every
 * seed on first call (several seconds), same reasoning as the alert
 * correlation engine's own /evaluation. */
export const useRansomEyeEvaluation = (options: SWRConfiguration = {}) => {
  const api = useApi();
  return useSWRImmutable<EvaluationResult>(
    api.isReady() ? "/ransomeye/evaluation" : null,
    (url: string) => api.get(url),
    options
  );
};
