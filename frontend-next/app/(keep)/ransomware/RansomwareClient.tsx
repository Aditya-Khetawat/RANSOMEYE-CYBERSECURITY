"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { GeistSans } from "geist/font/sans";
import { Text } from "@tremor/react";
import { useLoadScenario, useRansomEyeState } from "@/entities/ransomeye";
import type { ScenarioName } from "@/entities/ransomeye";
import { ScenarioControls } from "@/entities/ransomeye/ui/ScenarioControls";
import { CommandCenter } from "@/entities/ransomeye/ui/CommandCenter";
import { AlertBanner } from "@/entities/ransomeye/ui/AlertBanner";
import { EndpointFleetGrid } from "@/entities/ransomeye/ui/EndpointFleetGrid";
import { RiskGauge } from "@/entities/ransomeye/ui/RiskGauge";
import { ThreatFeed } from "@/entities/ransomeye/ui/ThreatFeed";
import { BehaviorTimeline } from "@/entities/ransomeye/ui/BehaviorTimeline";
import { EvidenceChain } from "@/entities/ransomeye/ui/EvidenceChain";
import { NetworkTopology } from "@/entities/ransomeye/ui/NetworkTopology";
import { ForecastPanel } from "@/entities/ransomeye/ui/ForecastPanel";
import { ContainmentPanel } from "@/entities/ransomeye/ui/ContainmentPanel";
import { CopilotPanel } from "@/entities/ransomeye/ui/CopilotPanel";

const TICK_MS = 650;

export function RansomwareClient() {
  const { data: run, isLoading: isLoadingState } = useRansomEyeState();
  const { loadScenario, isLoading: isLoadingScenario } = useLoadScenario();

  const [tickIndex, setTickIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const [contained, setContained] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // A freshly-loaded run always restarts the story from tick 0, autoplaying,
  // focused on whichever endpoint is the story's subject (or the first
  // endpoint for NORMAL_ACTIVITY, which has no target).
  useEffect(() => {
    if (!run) return;
    setTickIndex(0);
    setIsPlaying(true);
    setContained(false);
    setSelectedEndpointId(run.target_endpoint_id ?? run.endpoints[0]?.id ?? null);
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

  const handleRunScenario = async (scenario: ScenarioName) => {
    setIsPlaying(false);
    await loadScenario(scenario, 7);
  };

  const revealedTicks = useMemo(() => run?.ticks.slice(0, tickIndex + 1) ?? [], [run, tickIndex]);
  const currentTick = run?.ticks[tickIndex];
  const currentStates = currentTick?.endpoint_states ?? {};
  const activeAlerts = useMemo(
    () => revealedTicks.flatMap((t) => t.alerts),
    [revealedTicks]
  );
  const selectedState = selectedEndpointId ? currentStates[selectedEndpointId] : undefined;

  return (
    <div className={`${GeistSans.className} flex flex-col gap-4`}>
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-[11px] font-semibold tracking-[0.14em] uppercase text-red-500">
            AI-Powered · Real-Time Detection
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900">
          Ransomware Early Warning
        </h1>
        <Text className="text-sm text-gray-500 mt-1 max-w-2xl">
          Behavioral detection across file-system, process, privilege and network telemetry — built on the alert correlation engine&apos;s pipeline architecture, with a new ransomware-specific detection core.
        </Text>
      </div>

      <ScenarioControls
        run={run}
        isLoadingScenario={isLoadingScenario}
        onRunScenario={handleRunScenario}
        tickIndex={tickIndex}
        isPlaying={isPlaying}
        onTogglePlay={() => setIsPlaying((p) => !p)}
        onRestart={() => {
          setTickIndex(0);
          setIsPlaying(true);
        }}
        onScrub={(t) => {
          setIsPlaying(false);
          setTickIndex(t);
        }}
      />

      {!run && !isLoadingState && (
        <Text className="text-sm text-gray-500">
          Pick a scenario above to generate a fresh, reproducible telemetry timeline and watch it play out.
        </Text>
      )}

      {run && (
        <CommandCenter
          endpoints={run.endpoints}
          states={currentStates}
          ticks={revealedTicks}
          alert={activeAlerts[0]}
          contained={contained}
          targetEndpointId={run.target_endpoint_id}
        />
      )}

      {activeAlerts.map((alert) => (
        <AlertBanner key={alert.id} alert={alert} onInvestigate={() => setSelectedEndpointId(alert.endpoint_id)} />
      ))}

      {run && (
        <>
          <div className="grid lg:grid-cols-3 gap-4 items-start">
            <EndpointFleetGrid
              endpoints={run.endpoints}
              states={currentStates}
              selectedId={selectedEndpointId ?? ""}
              onSelect={setSelectedEndpointId}
            />
            {selectedState && selectedEndpointId && (
              <RiskGauge endpointId={selectedEndpointId} risk={selectedState.risk} />
            )}
            <ThreatFeed ticks={revealedTicks} />
          </div>

          {selectedEndpointId && (
            <BehaviorTimeline ticks={revealedTicks} endpointId={selectedEndpointId} />
          )}

          {selectedEndpointId && (
            <EvidenceChain
              ticks={revealedTicks}
              endpointId={selectedEndpointId}
              state={selectedState}
            />
          )}

          <NetworkTopology
            endpoints={run.endpoints}
            states={currentStates}
            alert={activeAlerts[0]}
            contained={contained}
            selectedEndpointId={selectedEndpointId}
            onSelect={setSelectedEndpointId}
          />

          {selectedEndpointId && (
            <div className="grid lg:grid-cols-3 gap-4 items-start">
              <ForecastPanel endpointId={selectedEndpointId} atTick={tickIndex} />
              <ContainmentPanel
                endpointId={selectedEndpointId}
                onContainmentApproved={() => setContained(true)}
              />
              <CopilotPanel endpointId={selectedEndpointId} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
