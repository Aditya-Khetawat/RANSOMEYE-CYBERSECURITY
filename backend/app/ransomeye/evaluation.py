"""Evaluation — "can we trust it?" Measures the detector against its own
generator's ground truth (RANSOMWARE_ATTACK should alert, NORMAL_ACTIVITY
and SUSPICIOUS_ACTIVITY should not) across a fixed seed set, the same
methodology the alert correlation engine uses for its own /evaluation
(see app/main.py's compute_evaluation and notebooks/poc_clustering.ipynb).

Nothing here is asserted: every run below actually executes demo.run_scenario
and reads whether an alert really fired, so precision/recall/F1 and the
detection lead time are measured, not fixed constants.
"""

from __future__ import annotations

from typing import Any

from . import demo

# Wider than the alert correlation engine's own 8-seed set (app/main.py
# EVAL_SEEDS) on purpose: telemetry.py's suspicious/ransomware intensity now
# varies per seed (a stealthy-to-loud spectrum, not a fixed narrow band), so
# more seeds are needed to actually exercise that range rather than sampling
# only its middle.
EVAL_SEEDS = [7, 42, 123, 2026, 555, 9, 77, 314, 1, 2, 3, 11, 99, 256, 512, 1024,
              2048, 4096, 31337, 8080, 65535, 12321, 555555, 20260902]

TICK_SECONDS = 30


def _detection_lead_seconds(run: dict) -> int | None:
    """Same measurement as the frontend's computeDetectionWindow (see
    entities/ransomeye/lib/attackStages.ts) — the gap between the alert
    firing and the tick where this endpoint's file modify+rename rate
    actually peaked, computed server-side so the evaluation page doesn't
    depend on the frontend ever having rendered this run."""
    if not run["alerts"]:
        return None
    alert = run["alerts"][0]
    ep_id = alert["endpoint_id"]

    peak_tick = alert["fired_at_tick"]
    peak_rate = -1.0
    for tick in run["ticks"]:
        feat = tick["endpoint_states"].get(ep_id, {}).get("feat")
        if not feat:
            continue
        rate = feat["file_mod_rate"] + feat["file_rename_rate"]
        if rate > peak_rate:
            peak_rate = rate
            peak_tick = tick["tick"]

    return max((peak_tick - alert["fired_at_tick"]) * TICK_SECONDS, 0)


def _peak_risk(run: dict) -> int:
    best = 0
    for tick in run["ticks"]:
        for state in tick["endpoint_states"].values():
            best = max(best, state["risk"]["score"])
    return best


def compute_evaluation() -> dict[str, Any]:
    """Runs every scenario at every seed once, for real, and measures the
    detector's outcomes against the generator's own ground truth:
    RANSOMWARE_ATTACK is a positive case (should fire), NORMAL_ACTIVITY and
    SUSPICIOUS_ACTIVITY are negative cases (should not) — SUSPICIOUS_ACTIVITY
    specifically because it's calibrated to be anomalous without being an
    attack, so it's the sharpest false-positive test available."""
    per_scenario: dict[str, dict[str, Any]] = {}
    lead_times: list[int] = []
    tp = fp = fn = tn = 0

    for scenario in demo.SCENARIOS:
        is_positive_case = scenario == "RANSOMWARE_ATTACK"
        runs = [demo.run_scenario(scenario, seed=seed) for seed in EVAL_SEEDS]
        fired = [bool(r["alerts"]) for r in runs]
        peak_risks = [_peak_risk(r) for r in runs]

        n_fired = sum(fired)
        if is_positive_case:
            tp += n_fired
            fn += len(runs) - n_fired
            lead_times += [lt for r in runs if (lt := _detection_lead_seconds(r)) is not None]
        else:
            fp += n_fired
            tn += len(runs) - n_fired

        entry: dict[str, Any] = {
            "seeds_tested": len(runs),
            "alerts_fired": n_fired,
            "expected_to_fire": is_positive_case,
            "fire_rate_pct": round(100 * n_fired / len(runs), 1),
            "mean_peak_risk": round(sum(peak_risks) / len(peak_risks), 1),
            "min_peak_risk": min(peak_risks),
            "max_peak_risk": max(peak_risks),
        }

        if is_positive_case:
            # Detection rate AND lead time matter more split by kill-chain
            # variant than pooled — a detector that only ever sees the full
            # seven-signal case could hide a stealthier attacker's numbers
            # behind a pooled average. See telemetry.py's skip_defense_evasion.
            for label, want_skip in (("full_kill_chain", False), ("smash_and_grab", True)):
                subset = [r for r in runs if bool((r.get("variant") or {}).get("skip_defense_evasion")) == want_skip]
                if subset:
                    n_sub_fired = sum(1 for r in subset if r["alerts"])
                    sub_leads = [lt for r in subset if (lt := _detection_lead_seconds(r)) is not None]
                    entry[label] = {
                        "seeds_tested": len(subset),
                        "alerts_fired": n_sub_fired,
                        "detection_rate_pct": round(100 * n_sub_fired / len(subset), 1),
                        "mean_lead_seconds": round(sum(sub_leads) / len(sub_leads), 1) if sub_leads else None,
                    }

        per_scenario[scenario] = entry

    precision = round(tp / (tp + fp), 3) if (tp + fp) else None
    recall = round(tp / (tp + fn), 3) if (tp + fn) else None
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else None
    false_positive_rate = round(fp / (fp + tn), 3) if (fp + tn) else None

    return {
        "seeds_tested": EVAL_SEEDS,
        "per_scenario": per_scenario,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "detection_lead_seconds": {
            "n": len(lead_times),
            "mean": round(sum(lead_times) / len(lead_times), 1) if lead_times else None,
            "min": min(lead_times) if lead_times else None,
            "max": max(lead_times) if lead_times else None,
        },
    }
