"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { TbBiohazard } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";

export function PageHead({
  eyebrow,
  title,
  sub,
}: {
  eyebrow: string;
  title: string;
  sub: string;
}) {
  return (
    <div className="mb-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-red-500">
        {eyebrow}
      </div>
      <h1 className="mt-1 text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl">
        {title}
      </h1>
      <p className="mt-1 max-w-2xl text-sm text-gray-500">{sub}</p>
    </div>
  );
}

/** Renders children only when a scenario run is loaded; otherwise a prompt. */
export function NeedsScenario({ children }: { children: ReactNode }) {
  const { run, isLoadingState } = useScenario();
  if (run) return <>{children}</>;
  return (
    <div className="rounded-xl border border-dashed border-gray-300 bg-white p-8 text-center">
      <TbBiohazard className="mx-auto h-8 w-8 text-gray-300" />
      <p className="mt-3 text-sm font-medium text-gray-700">
        {isLoadingState ? "Loading telemetry…" : "No scenario loaded"}
      </p>
      <p className="mt-1 text-xs text-gray-400">
        Pick a scenario in the bar above, or start from the{" "}
        <Link href="/" className="text-red-600 underline">
          Command Center
        </Link>
        .
      </p>
    </div>
  );
}

/** Renders children only when an endpoint is selected. */
export function NeedsEndpoint({ children }: { children: ReactNode }) {
  const { selectedEndpointId } = useScenario();
  if (selectedEndpointId) return <>{children}</>;
  return (
    <div className="rounded-xl border border-dashed border-gray-300 bg-white p-6 text-center text-sm text-gray-400">
      Select an endpoint (Command Center or Endpoint Fleet) to inspect it here.
    </div>
  );
}
