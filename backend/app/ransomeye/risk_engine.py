"""Ransomware Risk Engine — differentiator #1, same philosophy as the alert
correlation engine's risk_score.py (app/risk_score.py): a deliberately
explainable weighted heuristic over named, capped factors, not a black-box
model. Every input is something in features.py an analyst can point at;
every weight is written down here so it can be defended under judge
questioning.

    risk = 35% encryption_pattern + 25% process_behavior
         + 20% privilege_escalation + 20% network_abnormality

Output is 0..100 (not 0..1, unlike app/risk_score.py's escalation_risk())
because the PS explicitly asks for a 0-100 ransomware risk score.
"""

from __future__ import annotations

from typing import Any

CAPS = {
    "file_mod_rate": 12.0,
    "new_ext_convergence": 1.0,       # already a 0..1 ratio
    "entropy_flip_rate": 6.0,
    "file_rename_rate": 10.0,
    "process_spawn_rate": 3.0,
    # Low caps are deliberate, not tuning noise: baseline for both of these
    # is a written-down 0 (features.BASELINE) — a legitimate endpoint almost
    # never spawns a process carrying a suspicious indicator or fires a
    # privilege-escalation event, so a couple of real occurrences in one
    # rolling window should already read as most of the way to "max", not a
    # small fraction of it the way a rate-per-many-ticks metric normally would.
    "suspicious_process_rate": 0.5,
    "privilege_event_rate": 0.34,
    "network_conn_rate": 3.0,
    "malicious_conn_rate": 1.0,
    "external_conn_ratio": 1.0,
}

WEIGHTS = {
    "encryption_pattern": 0.35,
    "process_behavior": 0.25,
    "privilege_escalation": 0.20,
    "network_abnormality": 0.20,
}

LEVELS = [(85, "critical"), (60, "high"), (30, "medium"), (0, "low")]


def _norm(feat: dict, key: str) -> float:
    return min(feat.get(key, 0.0) / CAPS[key], 1.0)


def _encryption_pattern(feat: dict) -> float:
    """Mass rewrite rate + convergence onto one unfamiliar extension +
    plaintext-to-ciphertext entropy flips — the three signals that together
    are hard to produce with anything except bulk encryption in progress."""
    return round(
        0.40 * _norm(feat, "file_mod_rate")
        + 0.35 * _norm(feat, "new_ext_convergence")
        + 0.25 * _norm(feat, "entropy_flip_rate"),
        3,
    )


def _process_behavior(feat: dict) -> float:
    return round(
        0.70 * _norm(feat, "suspicious_process_rate")
        + 0.30 * _norm(feat, "process_spawn_rate"),
        3,
    )


def _privilege_escalation(feat: dict) -> float:
    return round(_norm(feat, "privilege_event_rate"), 3)


def _network_abnormality(feat: dict) -> float:
    return round(
        0.60 * _norm(feat, "malicious_conn_rate")
        + 0.25 * _norm(feat, "external_conn_ratio")
        + 0.15 * _norm(feat, "network_conn_rate"),
        3,
    )


def score_risk(feat: dict[str, Any], ml_anomaly_score: float | None = None) -> dict[str, Any]:
    """Returns the 0-100 score, level, per-category breakdown (each already
    weighted, so the UI can render a stacked bar that sums to the score), and
    the raw evidence strings features.py collected — that's what makes an
    alert actionable instead of just a number."""
    factors = {
        "encryption_pattern": _encryption_pattern(feat),
        "process_behavior": _process_behavior(feat),
        "privilege_escalation": _privilege_escalation(feat),
        "network_abnormality": _network_abnormality(feat),
    }
    weighted = {k: round(WEIGHTS[k] * v, 4) for k, v in factors.items()}
    score = round(sum(weighted.values()) * 100)
    level = next(name for threshold, name in LEVELS if score >= threshold)

    return {
        "score": score,
        "level": level,
        "factors": factors,
        "weighted_contribution_pct": {k: round(v * 100, 1) for k, v in weighted.items()},
        # Corroborating, not primary — see detector.py. Kept separate from
        # the weighted sum above so the headline score stays fully
        # inspectable (no factor whose provenance is "the model said so").
        "ml_anomaly_score": ml_anomaly_score,
        "evidence": feat.get("evidence", []),
    }
