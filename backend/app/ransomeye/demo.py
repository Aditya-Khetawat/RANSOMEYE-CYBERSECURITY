"""Scenario orchestrator — wires telemetry -> features -> detector ->
risk_engine -> alerts into one precomputed timeline per demo run, the
ransomware-detection equivalent of the alert correlation engine's
main.run_pipeline() (app/main.py).

The full timeline is computed once, server-side, and shipped to the frontend
in one response; the frontend animates through `ticks` client-side (same
"precompute once, replay client-side" shape as the alert correlation
engine's storm replay). This keeps the demo reliable and reproducible under
a seed — no live-loop timing to get wrong during a presentation.
"""

from __future__ import annotations

from typing import Any

from . import telemetry
from .alerts import maybe_fire_alert
from .detector import fit_anomaly_scores, rank_contributing_factors
from .features import extract_features
from .risk_engine import score_risk

SCENARIOS = ("NORMAL_ACTIVITY", "SUSPICIOUS_ACTIVITY", "RANSOMWARE_ATTACK")


def run_scenario(scenario: str, seed: int | None = None) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario!r}; must be one of {SCENARIOS}")

    raw = telemetry.generate_scenario(scenario, seed=seed)
    endpoints = raw["endpoints"]
    ep_ids = [e["id"] for e in endpoints]

    # Pass 1: extract features for every (endpoint, tick) — needed both for
    # the per-tick risk computation below and as the sample matrix the
    # IsolationForest in detector.py fits over.
    all_feats: dict[tuple[str, int], dict] = {}
    sample_order: list[tuple[str, int]] = []
    for tick_entry in raw["ticks"]:
        t = tick_entry["tick"]
        for ep_id in ep_ids:
            feat = extract_features(raw["ticks"], ep_id, t)
            all_feats[(ep_id, t)] = feat
            sample_order.append((ep_id, t))

    ml_scores = fit_anomaly_scores([all_feats[k] for k in sample_order])
    ml_score_by_key = dict(zip(sample_order, ml_scores))

    # Pass 2: score risk per (endpoint, tick), track alerts (fire once per
    # endpoint per run), assemble the final tick-by-tick payload.
    already_fired: set[str] = set()
    all_alerts: list[dict] = []
    ticks_out: list[dict] = []

    for tick_entry in raw["ticks"]:
        t = tick_entry["tick"]
        ts = tick_entry["ts"]
        endpoint_states: dict[str, dict] = {}
        new_alerts_this_tick: list[dict] = []

        for ep in endpoints:
            ep_id = ep["id"]
            feat = all_feats[(ep_id, t)]
            risk = score_risk(feat, ml_anomaly_score=ml_score_by_key[(ep_id, t)])
            risk["top_contributing_factors"] = rank_contributing_factors(feat)
            endpoint_states[ep_id] = {"feat": feat, "risk": risk}

            alert = maybe_fire_alert(ep, t, ts, risk, feat, ep_id in already_fired)
            if alert:
                already_fired.add(ep_id)
                new_alerts_this_tick.append(alert)
                all_alerts.append(alert)

        ticks_out.append({
            "tick": t,
            "ts": ts,
            "events_by_endpoint": tick_entry["events_by_endpoint"],
            "endpoint_states": endpoint_states,
            "alerts": new_alerts_this_tick,
        })

    peak = max(
        ((ep_id, ticks_out[-1]["endpoint_states"][ep_id]["risk"]["score"]) for ep_id in ep_ids),
        key=lambda x: x[1],
        default=(None, 0),
    )

    return {
        "scenario": scenario,
        "run_id": raw["run_id"],
        "endpoints": endpoints,
        "target_endpoint_id": raw["target_endpoint_id"],
        "ticks": ticks_out,
        "alerts": all_alerts,
        "summary": {
            "total_ticks": len(ticks_out),
            "total_alerts": len(all_alerts),
            "peak_risk_endpoint": peak[0],
            "peak_risk_score": peak[1],
            "final_status": (
                "CONTAINED_ALERT_FIRED" if all_alerts else
                "ANOMALY_OBSERVED_NO_ALERT" if scenario == "SUSPICIOUS_ACTIVITY" else
                "NORMAL"
            ),
        },
    }


def endpoint_risk_history(run: dict, endpoint_id: str, upto_tick: int | None = None) -> list[dict]:
    """This endpoint's [{tick, score, files_touched, file_mod_rate}, ...]
    across the run, oldest first, truncated at upto_tick if given."""
    history = []
    for tick_entry in run["ticks"]:
        if upto_tick is not None and tick_entry["tick"] > upto_tick:
            break
        state = tick_entry["endpoint_states"].get(endpoint_id)
        if not state:
            continue
        history.append({
            "tick": tick_entry["tick"],
            "score": state["risk"]["score"],
            "files_touched": state["feat"]["files_touched"],
            "file_mod_rate": state["feat"]["file_mod_rate"],
        })
    return history


def latest_endpoint_state(run: dict, endpoint_id: str, upto_tick: int | None = None) -> dict | None:
    for tick_entry in reversed(run["ticks"]):
        if upto_tick is not None and tick_entry["tick"] > upto_tick:
            continue
        state = tick_entry["endpoint_states"].get(endpoint_id)
        if state:
            return state
    return None


def latest_alert(run: dict, endpoint_id: str) -> dict | None:
    for alert in reversed(run["alerts"]):
        if alert["endpoint_id"] == endpoint_id:
            return alert
    return None
