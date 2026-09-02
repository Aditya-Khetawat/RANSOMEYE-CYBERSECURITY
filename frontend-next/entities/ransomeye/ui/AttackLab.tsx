"use client";

import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import {
  TbShieldCheck,
  TbShieldLock,
  TbAlertTriangle,
  TbPlayerPlayFilled,
  TbRefresh,
  TbCheck,
  TbActivity,
  TbFlask,
} from "react-icons/tb";
import {
  useAttackLab,
  useAttackLabControls,
  type LabProfile,
  type LabState,
} from "../model/useAttackLab";

/* ------------------------------------------------------------------ utils */

function useCountUp(target: number, active: boolean) {
  const [value, setValue] = useState(target);
  const from = useRef(target);
  const start = useRef<number | null>(null);
  useEffect(() => {
    if (!active) {
      setValue(target);
      from.current = target;
      return;
    }
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setValue(target);
      from.current = target;
      return;
    }
    from.current = value;
    start.current = null;
    let raf = 0;
    const dur = 450;
    const tick = (ts: number) => {
      if (start.current === null) start.current = ts;
      const p = Math.min((ts - start.current) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(Math.round(from.current + (target - from.current) * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
      else from.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, active]);
  return value;
}

const fmt = (n: number) => n.toLocaleString("en-US");
const clock = (iso: string) => (iso ? iso.slice(11, 19) : "--:--:--");
const secs = (s: number | null | undefined) =>
  s == null ? "—" : s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`;

const PROFILES: { key: LabProfile; label: string; blurb: string }[] = [
  { key: "NORMAL", label: "Normal", blurb: "Ordinary office activity — the true-negative baseline." },
  { key: "SUSPICIOUS", label: "Suspicious", blurb: "Nightly backup: heavy file churn, zero ransomware tradecraft." },
  { key: "RANSOMWARE", label: "Ransomware", blurb: "Full kill chain: staging → recovery inhibition → mass encryption." },
];

/* ------------------------------------------------------------------ shell */

export function AttackLab() {
  const { data } = useAttackLab();
  const { start, contain, reset, busy } = useAttackLabControls();
  const [profile, setProfile] = useState<LabProfile>("RANSOMWARE");

  const state: LabState = data ?? { status: "idle" };
  const running = state.status === "running" || state.status === "completed" || state.status === "contained";

  return (
    <div className="flex flex-col gap-5">
      <header>
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-orange-600">
          <TbFlask className="h-4 w-4" />
          RansomEye Attack Lab · Controlled Security Simulation
        </div>
        <h1 className="mt-1 text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl">
          Don&apos;t believe the dashboard. Watch us stop the attack.
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-gray-500">
          A benign simulator drives a real ransomware behaviour profile against a synthetic
          endpoint. Every file operation, process spawn and network beacon is scored live by
          RansomEye&apos;s actual detection pipeline — nothing here is pre-recorded, and nothing
          touches a real disk.
        </p>
      </header>

      {!running ? (
        <SetupCard profile={profile} onProfile={setProfile} onRun={() => start(profile)} busy={busy} />
      ) : (
        <LiveView state={state} onContain={contain} onReset={reset} busy={busy} />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ setup */

function SetupCard({
  profile,
  onProfile,
  onRun,
  busy,
}: {
  profile: LabProfile;
  onProfile: (p: LabProfile) => void;
  onRun: () => void;
  busy: boolean;
}) {
  return (
    <div className="rounded-2xl border border-gray-200 bg-white p-6">
      <div className="grid gap-6 md:grid-cols-[1fr_auto]">
        <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-3">
          <Field label="Target endpoint" value="FINANCE-WS-042" sub="finance-ws-042 · d.chen" />
          <Field label="Synthetic files" value="50,000" sub="Documents, spreadsheets, PDFs" />
          <Field label="Protection" value="OFF" sub="detector armed, response disabled" tone="danger" />
        </div>
        <div className="flex flex-col items-stretch justify-center gap-2">
          <button
            onClick={onRun}
            disabled={busy}
            className="flex items-center justify-center gap-2 rounded-xl bg-red-600 px-6 py-3 text-sm font-bold uppercase tracking-wide text-white shadow-sm transition hover:bg-red-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600 disabled:opacity-60"
          >
            <TbPlayerPlayFilled className="h-4 w-4" />
            Run Attack
          </button>
          <span className="text-center text-[11px] text-gray-400">seed 7 · reproducible</span>
        </div>
      </div>

      <div className="mt-6 border-t border-gray-100 pt-4">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          Behaviour profile
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          {PROFILES.map((p) => (
            <button
              key={p.key}
              onClick={() => onProfile(p.key)}
              className={clsx(
                "rounded-xl border p-3 text-left transition",
                profile === p.key
                  ? "border-orange-400 bg-orange-50"
                  : "border-gray-200 hover:border-gray-300"
              )}
            >
              <div className="text-sm font-semibold text-gray-900">{p.label}</div>
              <div className="mt-0.5 text-[11px] leading-snug text-gray-500">{p.blurb}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "default" | "danger";
}) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-gray-500">{label}</div>
      <div
        className={clsx(
          "mt-1 text-xl font-bold tabular-nums tracking-tight",
          tone === "danger" ? "text-red-600" : "text-gray-900"
        )}
      >
        {value}
      </div>
      {sub && <div className="text-[11px] text-gray-400">{sub}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ live */

function LiveView({
  state,
  onContain,
  onReset,
  busy,
}: {
  state: LabState;
  onContain: () => void;
  onReset: () => void;
  busy: boolean;
}) {
  const contained = state.status === "contained";
  const detection = state.detection ?? null;
  const cf = state.counterfactual ?? null;
  const corpus = state.corpus!;
  const risk = state.risk!;
  const tooLate = !contained && corpus.pct_encrypted >= (state.catastrophe_pct ?? 0.9);

  const touched = useCountUp(state.files_touched ?? 0, !contained);
  const pct = ((state.files_touched ?? 0) / corpus.total) * 100;

  // attack pressure: the live risk score, but held at its peak once the
  // instantaneous score decays after containment
  const peakRef = useRef(0);
  peakRef.current = Math.max(peakRef.current, risk.score);
  const pressure = contained ? Math.min(peakRef.current, 100) : risk.score;

  return (
    <div className="flex flex-col gap-4">
      {/* status strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3">
        <div className="flex items-center gap-4">
          <ProcessPill
            image={state.attacker!.image}
            pid={state.attacker!.pid}
            procState={state.attacker!.state}
          />
          <div className="hidden text-xs text-gray-400 sm:block">
            sim clock <span className="font-mono text-gray-600">{clock(state.sim_clock ?? "")}</span>
          </div>
        </div>
        <button
          onClick={onReset}
          disabled={busy}
          className="flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition hover:bg-gray-50"
        >
          <TbRefresh className="h-3.5 w-3.5" />
          Reset
        </button>
      </div>

      {/* counters */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Counter
          value={fmt(touched)}
          label={contained ? "Files touched before containment" : "Files affected"}
          tone="danger"
        />
        <Counter value={`${pct.toFixed(1)}%`} label="Corpus encrypted" tone={pct > 0 ? "danger" : "default"} />
        <Counter
          value={fmt(contained ? corpus.remaining : corpus.remaining)}
          label={contained ? "Files protected" : "Files remaining"}
          tone={contained ? "good" : "default"}
        />
      </div>

      {/* pressure bar */}
      <div className="rounded-xl border border-gray-200 bg-white p-4">
        <div className="mb-1.5 flex items-baseline justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">Attack pressure</span>
          <span
            className={clsx(
              "font-mono text-sm font-bold tabular-nums",
              pressure >= 60 ? "text-red-600" : pressure >= 30 ? "text-amber-600" : "text-emerald-600"
            )}
          >
            {pressure}/100
          </span>
        </div>
        <div className="h-2.5 overflow-hidden rounded-full bg-gray-100">
          <div
            className={clsx(
              "h-full rounded-full transition-[width] duration-500 ease-out motion-reduce:transition-none",
              pressure >= 60 ? "bg-red-500" : pressure >= 30 ? "bg-amber-500" : "bg-emerald-500"
            )}
            style={{ width: `${Math.max(pressure, 2)}%` }}
          />
        </div>
        {contained && (
          <div className="mt-2 text-[11px] text-gray-400">
            Frozen at peak — encryptor terminated, no further file operations.
          </div>
        )}
      </div>

      {/* signal panel */}
      <SignalPanel signals={state.signals ?? []} />

      {/* detection + contain */}
      {tooLate ? (
        <div className="rounded-xl border-2 border-gray-400 bg-gray-100 p-4 text-center">
          <div className="text-sm font-bold uppercase tracking-wide text-gray-700">
            Point of no return reached
          </div>
          <p className="mt-1 text-xs text-gray-500">
            No one hit Contain. {fmt(corpus.encrypted)} of {fmt(corpus.total)} files encrypted — this is
            what happens without an early-warning system. Reset and try again.
          </p>
        </div>
      ) : detection ? (
        <DetectionBanner
          detection={detection}
          contained={contained}
          onContain={onContain}
          busy={busy}
        />
      ) : (
        <div className="rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm text-gray-500">
          <TbActivity className="mr-1.5 inline h-4 w-4 animate-pulse text-gray-400" />
          Scoring telemetry… no ransomware behaviour crossed threshold yet.
        </div>
      )}

      {contained && <Containment state={state} />}

      {contained && cf && <Counterfactual state={state} />}

      {contained && (state.timeline?.length ?? 0) > 0 && (
        <SixtySecondWindow state={state} />
      )}

      {contained && <WhyWeStoppedIt state={state} />}

      {contained && (
        <div className="flex justify-center pt-1">
          <button
            onClick={onReset}
            disabled={busy}
            className="flex items-center gap-2 rounded-xl bg-gray-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-gray-800 disabled:opacity-60"
          >
            <TbRefresh className="h-4 w-4" />
            Run another attack
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ parts */

function ProcessPill({ image, pid, procState }: { image: string; pid: number; procState: string }) {
  const terminated = procState === "terminated";
  return (
    <div className="flex items-center gap-2 font-mono text-xs">
      <span
        className={clsx(
          "inline-block h-2 w-2 rounded-full",
          terminated ? "bg-gray-400" : "animate-pulse bg-red-500"
        )}
      />
      <span className={clsx("font-semibold", terminated ? "text-gray-400 line-through" : "text-gray-800")}>
        {image}
      </span>
      <span className="text-gray-400">pid {pid}</span>
      <span
        className={clsx(
          "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase",
          terminated
            ? "bg-gray-100 text-gray-500"
            : "bg-red-100 text-red-700"
        )}
      >
        {terminated ? "suspended" : procState}
      </span>
    </div>
  );
}

function Counter({ value, label, tone }: { value: string; label: string; tone: "default" | "danger" | "good" }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <div
        className={clsx(
          "font-mono text-3xl font-bold tabular-nums tracking-tight sm:text-4xl",
          tone === "danger" && "text-red-600",
          tone === "good" && "text-emerald-600",
          tone === "default" && "text-gray-900"
        )}
      >
        {value}
      </div>
      <div className="mt-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-gray-500">{label}</div>
    </div>
  );
}

function SignalPanel({ signals }: { signals: LabState["signals"] }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
        Behavioral signals
      </div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {(signals ?? []).map((s) => (
          <div key={s.key} className="rounded-lg border border-gray-100 p-2.5">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-400">{s.label}</div>
            <div
              className={clsx(
                "mt-0.5 font-mono text-sm font-bold",
                s.status === "critical" && "text-red-600",
                s.status === "warning" && "text-amber-600",
                s.status === "ok" && "text-gray-400"
              )}
            >
              {s.value}
            </div>
            <div className="mt-1 text-[10px] leading-tight text-gray-400">{s.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DetectionBanner({
  detection,
  contained,
  onContain,
  busy,
}: {
  detection: NonNullable<LabState["detection"]>;
  contained: boolean;
  onContain: () => void;
  busy: boolean;
}) {
  return (
    <div
      className={clsx(
        "rounded-xl border-2 p-4",
        contained
          ? "border-emerald-300 bg-emerald-50"
          : "border-red-400 bg-red-50"
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div
            className={clsx(
              "flex items-center gap-2 text-sm font-bold uppercase tracking-wide",
              contained ? "text-emerald-700" : "text-red-700"
            )}
          >
            {contained ? <TbShieldCheck className="h-5 w-5" /> : <TbAlertTriangle className="h-5 w-5 animate-pulse" />}
            {contained ? "Threat contained" : "Ransomware staging detected"}
          </div>
          <div className="mt-2 flex flex-wrap gap-6 font-mono text-xs">
            <Stat k="Confidence" v={`${detection.confidence}%`} />
            <Stat k="Detected at" v={clock(detection.sim_ts)} />
            <Stat k="Detection lead time" v={secs(detection.lead_seconds)} highlight />
          </div>
        </div>

        {!contained && (
          <button
            onClick={onContain}
            disabled={busy}
            className="flex items-center gap-2 rounded-xl bg-red-600 px-6 py-3 text-sm font-bold uppercase tracking-wide text-white shadow-sm transition hover:bg-red-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-700 disabled:opacity-60"
          >
            <TbShieldLock className="h-5 w-5" />
            Contain attack
          </button>
        )}
      </div>
    </div>
  );
}

function Stat({ k, v, highlight }: { k: string; v: string; highlight?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-gray-400">{k}</div>
      <div className={clsx("text-base font-bold", highlight ? "text-orange-600" : "text-gray-800")}>
        {v}
      </div>
    </div>
  );
}

function Containment({ state }: { state: LabState }) {
  const c = state.containment!;
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">Intervention</div>
      <ul className="grid gap-2 sm:grid-cols-2">
        {c.actions.map((a) => (
          <li key={a.label} className="flex items-start gap-2 text-sm">
            <TbCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
            <span>
              <span className="font-medium text-gray-900">{a.label}</span>
              <span className="block font-mono text-[11px] text-gray-400">{a.detail}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Counterfactual({ state }: { state: LabState }) {
  const cf = state.counterfactual!;
  const c = state.containment!;
  return (
    <div className="rounded-2xl border border-gray-200 bg-white p-5">
      <div className="mb-4 text-center text-sm font-bold uppercase tracking-[0.16em] text-gray-900">
        Same attack. Different outcome.
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <OutcomeColumn
          title="Without RansomEye"
          tone="bad"
          rows={[
            [`${fmt(cf.total_files)}`, "files at start"],
            ["Mass encryption", `runs unimpeded for ${secs(cf.sim_seconds_to_full)}`],
            [`${fmt(cf.files_encrypted)}`, `files encrypted (${(cf.pct_encrypted * 100).toFixed(0)}%)`],
            [cf.endpoint_status, "endpoint status"],
          ]}
        />
        <OutcomeColumn
          title="With RansomEye"
          tone="good"
          rows={[
            [`${fmt(cf.total_files)}`, "files at start"],
            ["Behaviour detected", `at ${clock(state.detection!.sim_ts)}, before encryption`],
            [`${fmt(c.files_touched_at_containment)}`, `files touched (${((c.files_touched_at_containment / cf.total_files) * 100).toFixed(1)}%)`],
            ["ISOLATED", "endpoint status — attack terminated"],
          ]}
        />
      </div>
      <div className="mt-4 rounded-lg bg-emerald-50 px-4 py-3 text-center text-sm font-semibold text-emerald-800">
        {fmt(c.files_protected)} files protected — {((c.files_protected / cf.total_files) * 100).toFixed(0)}% of the
        corpus never touched.
      </div>
    </div>
  );
}

function OutcomeColumn({
  title,
  tone,
  rows,
}: {
  title: string;
  tone: "bad" | "good";
  rows: [string, string][];
}) {
  return (
    <div
      className={clsx(
        "rounded-xl border p-4",
        tone === "bad"
          ? "border-red-200 bg-red-50/50"
          : "border-emerald-200 bg-emerald-50/50"
      )}
    >
      <div
        className={clsx(
          "mb-3 text-xs font-bold uppercase tracking-wide",
          tone === "bad" ? "text-red-700" : "text-emerald-700"
        )}
      >
        {title}
      </div>
      <div className="space-y-2">
        {rows.map(([v, k], i) => (
          <div key={i} className="flex items-baseline justify-between gap-3 border-b border-black/5 pb-1.5 last:border-0">
            <span className="font-mono text-sm font-bold text-gray-900">{v}</span>
            <span className="text-right text-[11px] text-gray-500">{k}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SixtySecondWindow({ state }: { state: LabState }) {
  const tl = state.timeline ?? [];
  const lead = state.detection?.lead_seconds ?? null;
  return (
    <div className="rounded-2xl border border-gray-200 bg-white p-5">
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">The 60-second window</div>
      <ol className="relative ml-2 border-l border-gray-200">
        {tl.map((e, i) => (
          <li key={i} className="mb-2.5 ml-4 last:mb-0">
            <span
              className={clsx(
                "absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full",
                e.kind === "warning"
                  ? "bg-orange-500"
                  : e.kind === "contained"
                    ? "bg-emerald-500"
                    : "bg-gray-300"
              )}
            />
            <div className="flex items-baseline gap-3">
              <span className="font-mono text-xs text-gray-400">{clock(e.sim_ts)}</span>
              <span
                className={clsx(
                  "text-sm",
                  e.kind === "warning"
                    ? "font-bold text-orange-600"
                    : e.kind === "contained"
                      ? "font-bold text-emerald-600"
                      : "text-gray-700"
                )}
              >
                {e.label}
              </span>
            </div>
          </li>
        ))}
      </ol>
      {lead != null && lead > 0 && (
        <div className="mt-4 text-center">
          <div className="font-mono text-3xl font-bold text-orange-600">{secs(lead)}</div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500">
            of advantage — warning to point-of-no-return
          </div>
        </div>
      )}
    </div>
  );
}

function WhyWeStoppedIt({ state }: { state: LabState }) {
  const observed = (state.signals ?? []).filter((s) => s.status !== "ok");
  const evidence = state.evidence ?? [];
  return (
    <div className="rounded-2xl border border-gray-200 bg-white p-5">
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">Why did we stop it?</div>
      <p className="mb-4 max-w-2xl text-sm text-gray-500">
        Not because a button said &ldquo;ransomware&rdquo;. {observed.length} independent behavioural
        signals converged inside one detection window, and the risk engine&apos;s weighted score
        crossed threshold on their combination.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        {observed.map((s, i) => (
          <span key={s.key} className="flex items-center gap-2">
            <span className="rounded-lg border border-gray-200 bg-gray-50 px-2.5 py-1 text-xs font-medium text-gray-700">
              {s.label} <span className="font-mono text-gray-400">{s.value}</span>
            </span>
            {i < observed.length - 1 && <span className="text-gray-300">+</span>}
          </span>
        ))}
        <span className="text-gray-300">→</span>
        <span className="rounded-lg bg-red-100 px-2.5 py-1 text-xs font-bold text-red-700">
          CONTAINMENT
        </span>
      </div>
      {evidence.length > 0 && (
        <ul className="mt-4 space-y-1 border-t border-gray-100 pt-3 text-[12px] text-gray-500">
          {evidence.slice(0, 5).map((e, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-gray-300">·</span>
              <span className="font-mono">{e}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
