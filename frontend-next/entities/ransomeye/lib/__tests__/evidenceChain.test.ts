import { buildEvidenceChain, deriveVerdict } from "../evidenceChain";
import type { Tick } from "../../model/types";

const EP = "WKS-1";

function tick(events: any[]): Tick {
  return { tick: 0, ts: "t", events_by_endpoint: { [EP]: events }, endpoint_states: {} } as unknown as Tick;
}
const state = (feat: Partial<Record<string, number>>) =>
  ({ feat: { file_mod_rate: 0, files_touched: 0, unique_extensions_touched: 0, ...feat } } as any);

const RANSOMWARE_TICKS = [
  tick([
    { type: "process", image: "powershell.exe", parent_image: "WINWORD.EXE", cmdline: "-enc …", ts: "t1", suspicious_indicators: ["encoded_command", "spawned_from_office_macro"] },
    { type: "network", reputation: "malicious", dest_ip: "185.220.101.45", bytes_out: 2000, ts: "t1" },
  ]),
  tick([
    { type: "process", image: "vssadmin.exe", cmdline: "delete shadows /all /quiet", ts: "t2", suspicious_indicators: ["shadow_copy_deletion"] },
    { type: "privilege", action: "token_elevation", detail: "elevated to SYSTEM", ts: "t2" },
  ]),
  tick([
    { type: "file", op: "rename", ext: ".docx", new_ext: ".ryxlock", entropy: 7.98, ts: "t3" },
    { type: "file", op: "rename", ext: ".txt", new_ext: ".ryxlock", entropy: 7.97, ts: "t3" },
  ]),
];

describe("buildEvidenceChain", () => {
  it("keeps both observed and unobserved signals (absences are part of the argument)", () => {
    const items = buildEvidenceChain([tick([])], EP, state({}));
    expect(items.length).toBeGreaterThanOrEqual(7);
    expect(items.every((i) => i.observed === false)).toBe(true);
  });

  it("marks the ransomware tradecraft signals observed from real events", () => {
    const byKey = Object.fromEntries(
      buildEvidenceChain(RANSOMWARE_TICKS, EP, state({ file_mod_rate: 12 })).map((i) => [i.key, i])
    );
    expect(byKey.malicious_execution.observed).toBe(true);
    expect(byKey.recovery_inhibition.observed).toBe(true);
    expect(byKey.privilege_escalation.observed).toBe(true);
    expect(byKey.mass_encryption.observed).toBe(true);
    expect(byKey.entropy_flip.observed).toBe(true);
    expect(byKey.c2_beacon.observed).toBe(true);
  });

  it("sorts observed signals ahead of absent ones", () => {
    const items = buildEvidenceChain(RANSOMWARE_TICKS, EP, state({ file_mod_rate: 12 }));
    const firstAbsent = items.findIndex((i) => !i.observed);
    const lastObserved = items.map((i) => i.observed).lastIndexOf(true);
    expect(lastObserved).toBeLessThan(firstAbsent);
  });

  it("attaches a real MITRE technique to the encryption signal", () => {
    const enc = buildEvidenceChain(RANSOMWARE_TICKS, EP, state({})).find((i) => i.key === "mass_encryption");
    expect(enc?.mitre?.id).toBe("T1486");
  });
});

describe("deriveVerdict", () => {
  it("calls RANSOMWARE LIKELY when >= 3 tradecraft signals corroborate", () => {
    const items = buildEvidenceChain(RANSOMWARE_TICKS, EP, state({ file_mod_rate: 12 }));
    expect(deriveVerdict(items, 60, 45).label).toBe("RANSOMWARE LIKELY");
  });

  it("never calls high churn with zero tradecraft 'ransomware', whatever the score", () => {
    const items = buildEvidenceChain([tick([{ type: "process", suspicious_indicators: ["unsigned_binary"], ts: "t" }])], EP, state({ file_mod_rate: 30 }));
    expect(deriveVerdict(items, 22, 22).label).toBe("NO THREAT DETECTED");
    expect(deriveVerdict(items, 40, 40).label).toBe("SUSPICIOUS — NOT RANSOMWARE");
  });

  it("excludes file_churn alone from tipping the verdict to ransomware", () => {
    const items = buildEvidenceChain([tick([])], EP, state({ file_mod_rate: 40 }));
    // file churn observed, zero tradecraft -> the ≥3 branch cannot trigger
    expect(deriveVerdict(items, 90, 90).label).not.toBe("RANSOMWARE LIKELY");
  });
});
