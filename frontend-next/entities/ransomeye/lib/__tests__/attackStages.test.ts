import { deriveAttackStages, computeDetectionWindow } from "../attackStages";
import type { EarlyWarningAlert, Tick } from "../../model/types";

const EP = "WKS-1";

function tick(n: number, events: any[], feat?: Partial<Record<string, number>>): Tick {
  return {
    tick: n,
    ts: `2026-01-01T10:${String(40 + n).padStart(2, "0")}:00`,
    events_by_endpoint: { [EP]: events },
    endpoint_states: {
      [EP]: {
        feat: { file_mod_rate: 0, file_rename_rate: 0, ...feat } as any,
        risk: { score: 0, level: "low", factors: {}, weighted_contribution_pct: {}, evidence: [] } as any,
      },
    },
  } as unknown as Tick;
}

const alert = (firedAtTick: number): EarlyWarningAlert =>
  ({ fired_at_tick: firedAtTick, timestamp: `2026-01-01T10:${String(40 + firedAtTick).padStart(2, "0")}:00` } as any);

describe("deriveAttackStages", () => {
  it("returns the seven stages in kill-chain order", () => {
    const stages = deriveAttackStages([], EP, undefined, false);
    expect(stages.map((s) => s.key)).toEqual([
      "initial_access",
      "privilege_escalation",
      "shadow_copy_deletion",
      "mass_encryption",
      "c2_beacon",
      "early_warning",
      "contained",
    ]);
  });

  it("marks nothing observed for an empty run", () => {
    const stages = deriveAttackStages([], EP, undefined, false);
    expect(stages.every((s) => s.observedAt === null)).toBe(true);
  });

  it("lights up each stage from its underlying telemetry evidence", () => {
    const ticks = [
      tick(2, [{ type: "process", suspicious_indicators: ["spawned_from_office_macro"], ts: "t2" }]),
      tick(3, [{ type: "network", reputation: "malicious", ts: "t3" }]),
      tick(6, [{ type: "process", suspicious_indicators: ["shadow_copy_deletion"], ts: "t6" }]),
      tick(7, [{ type: "privilege", action: "token_elevation", ts: "t7" }]),
      tick(9, [{ type: "file", op: "rename", new_ext: ".ryxlock", ts: "t9" }]),
    ];
    const seen = Object.fromEntries(
      deriveAttackStages(ticks, EP, undefined, false).map((s) => [s.key, s.observedAt])
    );
    expect(seen.initial_access).toBe("t2");
    expect(seen.c2_beacon).toBe("t3");
    expect(seen.shadow_copy_deletion).toBe("t6");
    expect(seen.privilege_escalation).toBe("t7");
    expect(seen.mass_encryption).toBe("t9");
    expect(seen.early_warning).toBeNull();
  });

  it("does NOT light up ransomware stages for benign churn (the honest signal)", () => {
    const ticks = [
      tick(1, [{ type: "file", op: "modify", ts: "t1" }, { type: "file", op: "create", ext: ".bkf", ts: "t1" }]),
      tick(2, [{ type: "process", suspicious_indicators: ["unsigned_binary"], ts: "t2" }]),
    ];
    const stages = deriveAttackStages(ticks, EP, undefined, false);
    expect(stages.every((s) => s.observedAt === null)).toBe(true);
  });

  it("adds early_warning and contained only with an alert", () => {
    const a = alert(8);
    expect(deriveAttackStages([], EP, a, false).find((s) => s.key === "early_warning")?.observedAt).toBe(a.timestamp);
    expect(deriveAttackStages([], EP, a, true).find((s) => s.key === "contained")?.observedAt).toBe(a.timestamp);
    expect(deriveAttackStages([], EP, undefined, true).find((s) => s.key === "contained")?.observedAt).toBeNull();
  });
});

describe("computeDetectionWindow", () => {
  it("is null with no alert", () => {
    expect(computeDetectionWindow([], EP, undefined).leadSeconds).toBeNull();
  });

  it("measures the gap from the alert to the peak file-rate tick", () => {
    const ticks = [
      tick(5, [], { file_mod_rate: 1, file_rename_rate: 0 }),
      tick(6, [], { file_mod_rate: 2, file_rename_rate: 3 }),
      tick(9, [], { file_mod_rate: 20, file_rename_rate: 10 }), // peak
      tick(12, [], { file_mod_rate: 4, file_rename_rate: 1 }),
    ];
    // alert fired at tick 6, peak at tick 9 -> 3 ticks * 30s
    expect(computeDetectionWindow(ticks, EP, alert(6)).leadSeconds).toBe(90);
  });

  it("never returns a negative lead time", () => {
    const ticks = [tick(3, [], { file_mod_rate: 30, file_rename_rate: 5 }), tick(9, [], { file_mod_rate: 1 })];
    expect(computeDetectionWindow(ticks, EP, alert(9)).leadSeconds).toBe(0);
  });
});
