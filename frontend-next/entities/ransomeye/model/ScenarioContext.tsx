"use client";

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useLoadScenario, useRansomEyeState } from "./useRansomEye";
import type {
  EarlyWarningAlert,
  EndpointState,
  ScenarioName,
  ScenarioRun,
  Tick,
} from "./types";

const TICK_MS = 650;

interface ScenarioContextValue {
  run: ScenarioRun | undefined;
  isLoadingState: boolean;
  isLoadingScenario: boolean;
  loadScenario: (scenario: ScenarioName) => Promise<void>;

  tickIndex: number;
  isPlaying: boolean;
  togglePlay: () => void;
  restart: () => void;
  scrub: (tick: number) => void;

  selectedEndpointId: string | null;
  selectEndpoint: (id: string | null) => void;

  contained: boolean;
  markContained: () => void;
  resetContained: () => void;

  /** Load a scenario (if not current), pause, jump to a tick, focus an
   * endpoint — one call. Used by the guided tour to stage each stop. */
  jumpTo: (opts: {
    scenario?: ScenarioName;
    tick?: number;
    endpointId?: string;
  }) => Promise<void>;

  // derived
  revealedTicks: Tick[];
  currentStates: Record<string, EndpointState>;
  activeAlerts: EarlyWarningAlert[];
  selectedState: EndpointState | undefined;
}

const ScenarioContext = createContext<ScenarioContextValue | null>(null);

export function ScenarioProvider({ children }: { children: ReactNode }) {
  const { data: run, isLoading: isLoadingState } = useRansomEyeState();
  const { loadScenario: doLoad, isLoading: isLoadingScenario } = useLoadScenario();

  const [tickIndex, setTickIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const [contained, setContained] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // When jumpTo() loads a scenario, it parks a target tick/endpoint here so
  // the run_id effect below lands there paused instead of autoplaying from 0.
  const pendingJump = useRef<{ tick?: number; endpointId?: string } | null>(null);

  // A freshly-loaded run restarts the story from tick 0, autoplaying, focused
  // on the story's subject endpoint — unless a jump is pending.
  useEffect(() => {
    if (!run) return;
    setContained(false);
    const jump = pendingJump.current;
    pendingJump.current = null;
    if (jump) {
      setIsPlaying(false);
      setTickIndex(jump.tick ?? 0);
      setSelectedEndpointId(
        jump.endpointId ?? run.target_endpoint_id ?? run.endpoints[0]?.id ?? null
      );
    } else {
      setTickIndex(0);
      setIsPlaying(true);
      setSelectedEndpointId(run.target_endpoint_id ?? run.endpoints[0]?.id ?? null);
    }
  }, [run?.run_id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!isPlaying || !run) return;
    timerRef.current = setInterval(() => {
      setTickIndex((i) => {
        if (i >= run.ticks.length - 1) {
          setIsPlaying(false);
          return i;
        }
        return i + 1;
      });
    }, TICK_MS);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, run]);

  const revealedTicks = useMemo(
    () => run?.ticks.slice(0, tickIndex + 1) ?? [],
    [run, tickIndex]
  );
  const currentStates = run?.ticks[tickIndex]?.endpoint_states ?? {};
  const activeAlerts = useMemo(
    () => revealedTicks.flatMap((t) => t.alerts),
    [revealedTicks]
  );
  const selectedState = selectedEndpointId ? currentStates[selectedEndpointId] : undefined;

  const value: ScenarioContextValue = {
    run,
    isLoadingState,
    isLoadingScenario,
    loadScenario: async (scenario) => {
      setIsPlaying(false);
      await doLoad(scenario, 7);
    },
    tickIndex,
    isPlaying,
    togglePlay: () => setIsPlaying((p) => !p),
    restart: () => {
      setTickIndex(0);
      setIsPlaying(true);
    },
    scrub: (t) => {
      setIsPlaying(false);
      setTickIndex(t);
    },
    selectedEndpointId,
    selectEndpoint: setSelectedEndpointId,
    contained,
    markContained: () => setContained(true),
    resetContained: () => setContained(false),
    jumpTo: async ({ scenario, tick, endpointId }) => {
      if (scenario && run?.scenario !== scenario) {
        // park the destination so the run_id effect lands there, paused
        pendingJump.current = { tick, endpointId };
        await doLoad(scenario, 7);
        await new Promise((r) => setTimeout(r, 400));
        return;
      }
      setIsPlaying(false);
      if (typeof tick === "number") setTickIndex(tick);
      if (endpointId) setSelectedEndpointId(endpointId);
    },
    revealedTicks,
    currentStates,
    activeAlerts,
    selectedState,
  };

  return <ScenarioContext.Provider value={value}>{children}</ScenarioContext.Provider>;
}

export function useScenario(): ScenarioContextValue {
  const ctx = useContext(ScenarioContext);
  if (!ctx) throw new Error("useScenario must be used inside <ScenarioProvider>");
  return ctx;
}
