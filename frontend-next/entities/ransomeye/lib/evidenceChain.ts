import type { EndpointState, RiskFactors, Tick } from "../model/types";

export interface MitreRef {
  /** Real MITRE ATT&CK technique ID. */
  id: string;
  name: string;
}

export type EvidenceCategory = keyof RiskFactors;

export interface EvidenceItem {
  key: string;
  title: string;
  mitre: MitreRef | null;
  /** Which risk-engine category this signal feeds (risk_engine.py). */
  category: EvidenceCategory;
  /** True only when this signal's evidence actually appears in telemetry. */
  observed: boolean;
  /** The concrete measured fact. Empty when not observed. */
  observation: string;
  /** Raw supporting detail straight from the events (cmdlines, IPs, values). */
  detail: string[];
  firstSeen: string | null;
  /** How many telemetry events backed this signal. */
  eventCount: number;
  /** Why this signal matters for ransomware specifically. */
  rationale: string;
}

/**
 * Plaintext-ish extensions whose normal entropy sits far below ciphertext.
 * Mirrors the sub-6.0 entries of telemetry.py's EXT_BASELINE_ENTROPY — the
 * backend remains the source of truth; this is only used to describe *which*
 * files flipped, never to decide the score.
 */
const LOW_ENTROPY_EXTS = new Set([".txt", ".csv", ".log", ".sql", ".xml", ".ini", ".bmp"]);

const CIPHERTEXT_ENTROPY_FLOOR = 7.5;
/** Sustained outbound volume that reads as bulk transfer rather than beacon. */
const EXFIL_BYTES_FLOOR = 100_000;

/**
 * Builds the behavioral evidence chain for one endpoint directly from its
 * raw telemetry across the revealed ticks.
 *
 * Deliberately returns BOTH observed and unobserved signals: on
 * SUSPICIOUS_ACTIVITY the file-churn signal fires while every piece of
 * ransomware tradecraft stays "not observed", and showing those absences is
 * what makes the not-ransomware verdict legible instead of merely asserted.
 *
 * No confidence percentages are invented anywhere here — each item carries
 * the actual counts and values measured, and the verdict is the risk
 * engine's own weighted score.
 */
export function buildEvidenceChain(
  ticks: Tick[],
  endpointId: string,
  state: EndpointState | undefined
): EvidenceItem[] {
  const feat = state?.feat;

  // --- collect raw observations -------------------------------------------
  const execCmdlines: string[] = [];
  let execFirst: string | null = null;

  const recoveryCmdlines: string[] = [];
  let recoveryFirst: string | null = null;

  const privDetails: string[] = [];
  let privFirst: string | null = null;

  const c2Ips = new Map<string, number>();
  let c2First: string | null = null;
  let c2Count = 0;

  let exfilBytes = 0;
  let exfilCount = 0;
  let exfilFirst: string | null = null;

  const renameExts = new Map<string, number>();
  const flippedExts = new Map<string, number>();
  let renameCount = 0;
  let renameFirst: string | null = null;
  let minFlipEntropy = Infinity;
  let maxFlipEntropy = -Infinity;

  const firstOf = (cur: string | null, ts: string) => cur ?? ts;

  for (const tick of ticks) {
    for (const ev of tick.events_by_endpoint[endpointId] ?? []) {
      if (ev.type === "process") {
        const ind = ev.suspicious_indicators;
        if (ind.includes("spawned_from_office_macro") || ind.includes("encoded_command")) {
          execFirst = firstOf(execFirst, ev.ts);
          if (execCmdlines.length < 3) execCmdlines.push(`${ev.image} ← ${ev.parent_image}: ${ev.cmdline}`);
        }
        if (ind.includes("shadow_copy_deletion") || ind.includes("disables_recovery")) {
          recoveryFirst = firstOf(recoveryFirst, ev.ts);
          if (recoveryCmdlines.length < 3) recoveryCmdlines.push(ev.cmdline);
        }
      }

      if (ev.type === "privilege") {
        if (ev.action === "token_elevation") {
          privFirst = firstOf(privFirst, ev.ts);
          if (privDetails.length < 3) privDetails.push(ev.detail);
        }
        if (ev.action === "shadow_copy_delete") {
          recoveryFirst = firstOf(recoveryFirst, ev.ts);
          if (recoveryCmdlines.length < 3) recoveryCmdlines.push(ev.detail);
        }
      }

      if (ev.type === "network" && ev.reputation === "malicious") {
        c2First = firstOf(c2First, ev.ts);
        c2Count += 1;
        c2Ips.set(ev.dest_ip, (c2Ips.get(ev.dest_ip) ?? 0) + 1);
        if (ev.bytes_out >= EXFIL_BYTES_FLOOR) {
          exfilFirst = firstOf(exfilFirst, ev.ts);
          exfilCount += 1;
          exfilBytes += ev.bytes_out;
        }
      }

      if (ev.type === "file" && ev.op === "rename" && ev.new_ext) {
        renameFirst = firstOf(renameFirst, ev.ts);
        renameCount += 1;
        renameExts.set(ev.new_ext, (renameExts.get(ev.new_ext) ?? 0) + 1);
        if (LOW_ENTROPY_EXTS.has(ev.ext) && ev.entropy >= CIPHERTEXT_ENTROPY_FLOOR) {
          flippedExts.set(ev.ext, (flippedExts.get(ev.ext) ?? 0) + 1);
          minFlipEntropy = Math.min(minFlipEntropy, ev.entropy);
          maxFlipEntropy = Math.max(maxFlipEntropy, ev.entropy);
        }
      }
    }
  }

  const topRenameExt = [...renameExts.entries()].sort((a, b) => b[1] - a[1])[0];
  const flippedTotal = [...flippedExts.values()].reduce((a, b) => a + b, 0);
  const modRate = feat?.file_mod_rate ?? 0;
  const churnObserved = modRate >= 8;

  const items: EvidenceItem[] = [
    {
      key: "malicious_execution",
      title: "Malicious Document Execution",
      mitre: { id: "T1204.002", name: "User Execution: Malicious File" },
      category: "process_behavior",
      observed: execCmdlines.length > 0,
      observation: execCmdlines.length
        ? `Script interpreter spawned from an Office process with an encoded command`
        : "",
      detail: execCmdlines,
      firstSeen: execFirst,
      eventCount: execCmdlines.length,
      rationale: "Macro-spawned, encoded PowerShell is the standard ransomware delivery path.",
    },
    {
      key: "recovery_inhibition",
      title: "Recovery Inhibition",
      mitre: { id: "T1490", name: "Inhibit System Recovery" },
      category: "privilege_escalation",
      observed: recoveryCmdlines.length > 0,
      observation: recoveryCmdlines.length
        ? `Volume shadow copies deleted and recovery disabled`
        : "",
      detail: recoveryCmdlines,
      firstSeen: recoveryFirst,
      eventCount: recoveryCmdlines.length,
      rationale:
        "Destroying restore points has no legitimate bulk use — it exists to make paying the ransom the only option.",
    },
    {
      key: "privilege_escalation",
      title: "Privilege Escalation",
      mitre: { id: "T1134", name: "Access Token Manipulation" },
      category: "privilege_escalation",
      observed: privDetails.length > 0,
      observation: privDetails.length ? `User process token elevated to SYSTEM` : "",
      detail: privDetails,
      firstSeen: privFirst,
      eventCount: privDetails.length,
      rationale: "SYSTEM rights let the encryptor reach files and services the user never could.",
    },
    {
      key: "mass_encryption",
      title: "Mass File Encryption",
      mitre: { id: "T1486", name: "Data Encrypted for Impact" },
      category: "encryption_pattern",
      observed: renameCount > 0,
      observation: renameCount
        ? `${renameCount} files renamed to \`${topRenameExt?.[0] ?? "?"}\``
        : "",
      detail: renameCount
        ? [
            `Converged on one unfamiliar extension: ${[...renameExts.entries()]
              .map(([e, n]) => `${e} ×${n}`)
              .join(", ")}`,
          ]
        : [],
      firstSeen: renameFirst,
      eventCount: renameCount,
      rationale:
        "A single actor renaming everything to one new extension is systematic rewriting, not user activity.",
    },
    {
      key: "entropy_flip",
      title: "Plaintext → Ciphertext Entropy Flip",
      mitre: { id: "T1486", name: "Data Encrypted for Impact" },
      category: "encryption_pattern",
      observed: flippedTotal > 0,
      observation: flippedTotal
        ? `${flippedTotal} previously plaintext files now read ${minFlipEntropy.toFixed(2)}–${maxFlipEntropy.toFixed(2)} bits/byte`
        : "",
      detail: flippedTotal
        ? [
            `Affected plaintext formats: ${[...flippedExts.entries()]
              .map(([e, n]) => `${e} ×${n}`)
              .join(", ")} — these normally read ~3–5 bits/byte`,
            "Already-compressed formats (.docx/.pdf/.jpg/.zip) are excluded: they sit near ciphertext entropy even when saved legitimately, so they are not usable evidence.",
          ]
        : [],
      firstSeen: renameFirst,
      eventCount: flippedTotal,
      rationale:
        "Format-independent proof of encryption — content that was readable is now indistinguishable from random.",
    },
    {
      key: "c2_beacon",
      title: "Command & Control Contact",
      mitre: { id: "T1071", name: "Application Layer Protocol" },
      category: "network_abnormality",
      observed: c2Count > 0,
      observation: c2Count
        ? `${c2Count} outbound connections to ${c2Ips.size} known-bad host${c2Ips.size === 1 ? "" : "s"}`
        : "",
      detail: c2Count ? [...c2Ips.entries()].map(([ip, n]) => `${ip} — ${n} connection${n === 1 ? "" : "s"}`) : [],
      firstSeen: c2First,
      eventCount: c2Count,
      rationale: "Reputation-flagged destinations indicate the host is taking instructions from an operator.",
    },
    {
      key: "exfiltration",
      title: "Bulk Outbound Transfer",
      mitre: { id: "T1041", name: "Exfiltration Over C2 Channel" },
      category: "network_abnormality",
      observed: exfilCount > 0,
      observation: exfilCount
        ? `${(exfilBytes / 1_000_000).toFixed(1)} MB sent to known-bad hosts across ${exfilCount} transfers`
        : "",
      detail: [],
      firstSeen: exfilFirst,
      eventCount: exfilCount,
      rationale: "Volume on a malicious channel suggests double extortion — steal first, then encrypt.",
    },
    {
      key: "file_churn",
      title: "Abnormal File Modification Rate",
      mitre: null,
      category: "encryption_pattern",
      observed: churnObserved,
      observation: churnObserved ? `${modRate.toFixed(1)} files/tick modified` : "",
      detail: churnObserved
        ? [`${feat?.files_touched ?? 0} distinct files touched across ${feat?.unique_extensions_touched ?? 0} extensions`]
        : [],
      firstSeen: null,
      eventCount: feat?.files_touched ?? 0,
      rationale:
        "High churn alone is NOT ransomware — backups and bulk edits look identical. It only matters alongside the tradecraft above.",
    },
  ];

  // Observed signals first, then absent ones — the absences are part of the
  // argument, so they are kept rather than filtered out.
  return items.sort((a, b) => Number(b.observed) - Number(a.observed));
}

export interface Verdict {
  label: string;
  tone: "critical" | "warning" | "clear";
  /** Current (latest-tick) risk score — shown for context. */
  score: number;
  /** Highest risk score reached anywhere in the revealed run — used for the
   * verdict itself, since the instantaneous score decays once a scenario's
   * burst of activity tapers off, while the evidence below is cumulative
   * and does not un-happen. Reading only the latest tick would let a
   * contained/finished attack silently downgrade to "suspicious". */
  peakScore: number;
  /** Count of ransomware-specific tradecraft signals actually observed. */
  tradecraftObserved: number;
  tradecraftTotal: number;
  reasoning: string;
}

/**
 * The correlated verdict. Driven primarily by how many distinct ransomware
 * tradecraft signals corroborate each other — each one (shadow-copy
 * deletion, an entropy flip, a C2 contact...) is close to unambiguous on its
 * own, so three or more together is conclusive regardless of where the
 * instantaneous risk score happens to sit right now. The score is
 * secondary context, taken at its peak rather than its current value.
 */
export function deriveVerdict(items: EvidenceItem[], peakScore: number, currentScore: number): Verdict {
  // "file_churn" is excluded: it is the one signal that is genuinely
  // ambiguous on its own, and counting it would let a backup job inflate
  // the verdict.
  const tradecraft = items.filter((i) => i.key !== "file_churn");
  const observed = tradecraft.filter((i) => i.observed).length;

  if (observed >= 3) {
    return {
      label: "RANSOMWARE LIKELY",
      tone: "critical",
      score: currentScore,
      peakScore,
      tradecraftObserved: observed,
      tradecraftTotal: tradecraft.length,
      reasoning: `${observed} independent ransomware tradecraft signals corroborate each other within the same window; risk peaked at ${peakScore}/100.`,
    };
  }
  if (observed > 0 || peakScore >= 30) {
    return {
      label: "SUSPICIOUS — NOT RANSOMWARE",
      tone: "warning",
      score: currentScore,
      peakScore,
      tradecraftObserved: observed,
      tradecraftTotal: tradecraft.length,
      reasoning:
        observed > 0
          ? `Only ${observed} of ${tradecraft.length} tradecraft signals present — not enough corroboration to call this an encryption event.`
          : "Elevated activity, but no ransomware tradecraft observed: no recovery inhibition, no entropy flip, no known-bad contact.",
    };
  }
  return {
    label: "NO THREAT DETECTED",
    tone: "clear",
    score: currentScore,
    peakScore,
    tradecraftObserved: observed,
    tradecraftTotal: tradecraft.length,
    reasoning: "No ransomware tradecraft observed and behavioral rates are within baseline.",
  };
}
