"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import clsx from "clsx";
import { TbArrowLeft, TbArrowRight, TbX, TbPlayerPlayFilled } from "react-icons/tb";
import { useScenario } from "../model/ScenarioContext";
import { useTour } from "../model/TourContext";
import { TOUR_STEPS, type TourRunCtx } from "../model/tourSteps";
import { useAttackLab, useAttackLabControls } from "../model/useAttackLab";

export function GuidedTour() {
  const { active } = useTour();
  if (!active) return null;
  return <TourRunner />;
}

/* ---------------------------------------------------------------- spotlight */

function useSpotlightRect(key: string | undefined, revision: number) {
  const [rect, setRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    if (!key) {
      setRect(null);
      return;
    }
    let raf = 0;
    let tries = 0;
    let settle: ReturnType<typeof setTimeout>;
    const find = () => {
      const el = document.querySelector<HTMLElement>(`[data-tour="${key}"]`);
      if (el) {
        el.scrollIntoView({ block: "center", behavior: "smooth" });
        settle = setTimeout(() => setRect(el.getBoundingClientRect()), 280);
      } else if (tries++ < 60) {
        raf = requestAnimationFrame(find);
      } else {
        setRect(null);
      }
    };
    raf = requestAnimationFrame(find);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(settle);
    };
  }, [key, revision]);

  useEffect(() => {
    if (!key) return;
    const remeasure = () => {
      const el = document.querySelector<HTMLElement>(`[data-tour="${key}"]`);
      if (el) setRect(el.getBoundingClientRect());
    };
    window.addEventListener("resize", remeasure);
    window.addEventListener("scroll", remeasure, true);
    const iv = setInterval(remeasure, 400);
    return () => {
      window.removeEventListener("resize", remeasure);
      window.removeEventListener("scroll", remeasure, true);
      clearInterval(iv);
    };
  }, [key]);

  return rect;
}

/* ------------------------------------------------------------------ runner */

function TourRunner() {
  const { step, total, next, prev, exit, goto } = useTour();
  const scenario = useScenario();
  const { data: lab } = useAttackLab();
  const { start: startLab, contain: containLab } = useAttackLabControls();
  const router = useRouter();
  const pathname = usePathname();

  const current = TOUR_STEPS[step];
  const [staging, setStaging] = useState(true);
  const runToken = useRef(0);

  // keep latest lab/controls for the step's run() without re-triggering it
  const ctxRef = useRef<TourRunCtx>({ scenario, lab, startLab, containLab });
  ctxRef.current = { scenario, lab, startLab, containLab };

  // On step change: route there, then stage the app for the step.
  useEffect(() => {
    const token = ++runToken.current;
    setStaging(true);
    if (pathname !== current.path) router.push(current.path);
    (async () => {
      try {
        await current.run?.(ctxRef.current);
      } catch {
        /* staging is best-effort */
      }
      if (runToken.current === token) setStaging(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const rect = useSpotlightRect(current.spotlight, step);

  // keyboard
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") exit();
      else if (e.key === "ArrowRight" || e.key === " ") {
        e.preventDefault();
        step === total - 1 ? exit() : next();
      } else if (e.key === "ArrowLeft") prev();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [step, total, next, prev, exit]);

  const pad = 10;
  const hole =
    rect && rect.width > 0
      ? {
          top: Math.max(rect.top - pad, 4),
          left: Math.max(rect.left - pad, 4),
          width: rect.width + pad * 2,
          height: rect.height + pad * 2,
        }
      : null;

  const isFirst = step === 0;
  const isLast = step === total - 1;

  return (
    <div className="fixed inset-0 z-[120] pointer-events-none">
      {/* top progress bar */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-0.5 bg-slate-900/10">
        <div
          className="h-full bg-orange-500 transition-[width] duration-500"
          style={{ width: `${((step + 1) / total) * 100}%` }}
        />
      </div>

      {/* dimmer + spotlight */}
      {hole ? (
        <div
          aria-hidden
          className="absolute rounded-xl ring-2 ring-orange-400 transition-all duration-300 ease-out motion-reduce:transition-none"
          style={{
            top: hole.top,
            left: hole.left,
            width: hole.width,
            height: hole.height,
            boxShadow: "0 0 0 100vmax rgba(15,23,42,0.60)",
          }}
        />
      ) : (
        <div aria-hidden className="absolute inset-0 bg-slate-900/60" />
      )}

      {/* caption card — pinned bottom-centre */}
      <div className="pointer-events-auto absolute inset-x-0 bottom-0 flex justify-center px-3 pb-4 sm:pb-6">
        <div
          role="dialog"
          aria-modal="true"
          aria-label="RansomEye guided tour"
          className="w-full max-w-[460px] rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl shadow-slate-900/20"
        >
          <div className="flex items-start justify-between gap-3">
            <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-orange-600">
              {current.eyebrow}
            </span>
            <button
              onClick={exit}
              className="-mr-1 -mt-1 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
              aria-label="Exit tour"
            >
              <TbX className="h-4 w-4" />
            </button>
          </div>

          <h2 className="mt-1.5 text-base font-bold leading-snug text-slate-900 text-balance">
            {current.title}
          </h2>
          <p className="mt-1.5 text-[13px] leading-relaxed text-slate-600">{current.body}</p>
          {current.hint && (
            <p className="mt-2 flex gap-1.5 text-[11.5px] leading-snug text-orange-700">
              <span aria-hidden>↳</span>
              <span>{current.hint}</span>
            </p>
          )}

          <div className="mt-4 flex items-center justify-between">
            <div className="flex gap-1" aria-hidden>
              {TOUR_STEPS.map((s, i) => (
                <button
                  key={s.id}
                  onClick={() => goto(i)}
                  className={clsx(
                    "h-1.5 rounded-full transition-all",
                    i === step ? "w-5 bg-orange-500" : "w-1.5 bg-slate-200 hover:bg-slate-300"
                  )}
                  aria-label={`Go to step ${i + 1}`}
                />
              ))}
            </div>

            <div className="flex items-center gap-1.5">
              {!isFirst && (
                <button
                  onClick={prev}
                  className="flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50"
                >
                  <TbArrowLeft className="h-3.5 w-3.5" />
                  Back
                </button>
              )}
              <button
                onClick={isLast ? exit : next}
                className="flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-bold text-white hover:bg-slate-800"
              >
                {isLast ? "Finish" : staging ? "Staging…" : "Next"}
                {!isLast && <TbArrowRight className="h-3.5 w-3.5" />}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- launch pill */

export function JudgeModeButton({ variant = "pill" }: { variant?: "pill" | "sidebar" }) {
  const { start, active } = useTour();
  if (active) return null;

  if (variant === "sidebar") {
    return (
      <button
        onClick={start}
        data-testid="judge-mode"
        className="mx-1 mb-2 flex w-[calc(100%-0.5rem)] items-center justify-center gap-1.5 rounded-lg bg-orange-600 px-3 py-2 text-xs font-bold uppercase tracking-wide text-white shadow-sm transition hover:bg-orange-700"
      >
        <TbPlayerPlayFilled className="h-3.5 w-3.5" />
        Judge Mode
      </button>
    );
  }

  return (
    <button
      onClick={start}
      data-testid="judge-mode"
      className="fixed bottom-4 left-4 z-[90] flex items-center gap-1.5 rounded-full border border-orange-300 bg-white/95 px-3.5 py-2 text-xs font-bold text-orange-700 shadow-lg shadow-slate-900/10 backdrop-blur transition hover:bg-orange-50"
    >
      <TbPlayerPlayFilled className="h-3.5 w-3.5" />
      Judge Mode · 3-min tour
    </button>
  );
}
