"use client";

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { TOUR_STEPS } from "./tourSteps";

interface TourContextValue {
  active: boolean;
  step: number;
  total: number;
  start: () => void;
  exit: () => void;
  next: () => void;
  prev: () => void;
  goto: (i: number) => void;
}

const TourContext = createContext<TourContextValue | null>(null);

export function TourProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState(false);
  const [step, setStep] = useState(0);
  const total = TOUR_STEPS.length;

  const start = useCallback(() => {
    setStep(0);
    setActive(true);
  }, []);
  const exit = useCallback(() => setActive(false), []);
  const next = useCallback(() => setStep((s) => Math.min(s + 1, total - 1)), [total]);
  const prev = useCallback(() => setStep((s) => Math.max(s - 1, 0)), []);
  const goto = useCallback((i: number) => setStep(() => Math.max(0, Math.min(i, total - 1))), [total]);

  return (
    <TourContext.Provider value={{ active, step, total, start, exit, next, prev, goto }}>
      {children}
    </TourContext.Provider>
  );
}

export function useTour(): TourContextValue {
  const ctx = useContext(TourContext);
  if (!ctx) throw new Error("useTour must be used inside <TourProvider>");
  return ctx;
}
