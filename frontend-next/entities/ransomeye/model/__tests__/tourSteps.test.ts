import { TOUR_STEPS } from "../tourSteps";

const ROUTES = new Set(["/", "/detection", "/evidence", "/blast-radius", "/containment", "/lab", "/evaluation", "/fleet", "/incidents"]);
const SPOTLIGHTS = new Set([
  "command-center",
  "detection-verdict",
  "evidence-chain",
  "blast-horizons",
  "containment-actions",
  "lab-live",
  "lab-outcome",
  "eval-metrics",
]);

describe("TOUR_STEPS", () => {
  it("is a concise walkthrough (<= 10 stops)", () => {
    expect(TOUR_STEPS.length).toBeGreaterThanOrEqual(7);
    expect(TOUR_STEPS.length).toBeLessThanOrEqual(10);
  });

  it("every step points at a real route", () => {
    for (const s of TOUR_STEPS) expect(ROUTES.has(s.path)).toBe(true);
  });

  it("every spotlight refers to a known data-tour anchor", () => {
    for (const s of TOUR_STEPS) {
      if (s.spotlight) expect(SPOTLIGHTS.has(s.spotlight)).toBe(true);
    }
  });

  it("has unique step ids and non-empty copy", () => {
    expect(new Set(TOUR_STEPS.map((s) => s.id)).size).toBe(TOUR_STEPS.length);
    for (const s of TOUR_STEPS) {
      expect(s.title.length).toBeGreaterThan(8);
      expect(s.body.length).toBeGreaterThan(40);
      expect(s.eyebrow).toMatch(/\d+\s*\/\s*\d+/);
    }
  });

  it("numbers the eyebrows sequentially against the total", () => {
    const total = TOUR_STEPS.length;
    TOUR_STEPS.forEach((s, i) => {
      const m = s.eyebrow.match(/(\d+)\s*\/\s*(\d+)/)!;
      expect(Number(m[1])).toBe(i + 1);
      expect(Number(m[2])).toBe(total);
    });
  });

  it("tells the SEE / PROVE / UNDERSTAND / PREDICT / STOP story", () => {
    const phases = TOUR_STEPS.map((s) => s.eyebrow.split("·")[0].trim().toLowerCase());
    expect(phases).toEqual(expect.arrayContaining(["see", "understand", "predict", "stop", "prove"]));
  });

  it("drives the Attack Lab as the proof step", () => {
    const lab = TOUR_STEPS.filter((s) => s.path === "/lab");
    expect(lab.length).toBe(2);
    expect(lab.some((s) => s.run)).toBe(true);
  });
});
