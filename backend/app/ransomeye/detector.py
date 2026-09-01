"""Behavioral anomaly detection — lightweight, corroborating layer on top of
the explainable risk_engine.py score.

Two pieces, deliberately kept separate from the headline risk score:

1. `rank_contributing_factors` — trailing-window rolling stats vs. a written-
   down normal baseline (features.BASELINE), ranked by how far each feature
   deviates. This is what "contributing behaviors" in an alert actually is.

2. `fit_anomaly_scores` — an IsolationForest over every endpoint's feature
   vectors for the currently-loaded scenario run. Isolation Forest suits this
   better than a distance/density method here: it's O(n log n), needs no
   distributional assumptions, and (unlike TF-IDF+DBSCAN, which the alert
   correlation engine uses for clustering *text*) operates directly on the
   numeric behavioral feature vectors this module produces — a shape
   TF-IDF/DBSCAN was never
   meant for. Its output is surfaced as `ml_anomaly_score`, a corroborating
   badge — never the primary driver of the 0-100 score, which stays the
   fully inspectable weighted sum in risk_engine.py.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from .features import BASELINE

FEATURE_KEYS = [
    "file_mod_rate", "file_rename_rate", "new_ext_convergence", "entropy_flip_rate",
    "process_spawn_rate", "suspicious_process_rate", "privilege_event_rate",
    "network_conn_rate", "malicious_conn_rate", "external_conn_ratio",
]

# Deviation caps mirroring risk_engine.CAPS, used only to normalize the
# ranking below to a comparable 0..1 scale per factor — not part of scoring.
_DEV_CAP = {
    "file_mod_rate": 12.0, "file_rename_rate": 10.0, "new_ext_convergence": 1.0,
    "entropy_flip_rate": 6.0, "process_spawn_rate": 3.0, "suspicious_process_rate": 0.5,
    "privilege_event_rate": 0.34, "network_conn_rate": 3.0, "malicious_conn_rate": 1.0,
    "external_conn_ratio": 1.0,
}

LABELS = {
    "file_mod_rate": "File modification rate",
    "file_rename_rate": "File rename rate",
    "new_ext_convergence": "Mass rename to one unfamiliar extension",
    "entropy_flip_rate": "Plaintext-to-ciphertext entropy flips",
    "process_spawn_rate": "Process spawn rate",
    "suspicious_process_rate": "Suspicious process indicators",
    "privilege_event_rate": "Privilege escalation events",
    "network_conn_rate": "Network connection rate",
    "malicious_conn_rate": "Connections to known-bad hosts",
    "external_conn_ratio": "External connection ratio",
}


def rank_contributing_factors(feat: dict[str, Any], top_n: int = 4) -> list[dict[str, Any]]:
    """Ranks features by (value - baseline) / cap, descending. Zero-baseline
    features (privilege events, malicious conns, entropy flips) rank by raw
    normalized value since any nonzero occurrence is itself the deviation."""
    ranked = []
    for key in FEATURE_KEYS:
        value = feat.get(key, 0.0)
        baseline = BASELINE.get(key, 0.0)
        deviation = max(value - baseline, 0.0) / _DEV_CAP[key]
        if deviation <= 0:
            continue
        ranked.append({
            "factor": LABELS[key],
            "key": key,
            "value": value,
            "baseline": baseline,
            "deviation": round(min(deviation, 1.0), 3),
        })
    ranked.sort(key=lambda r: r["deviation"], reverse=True)
    return ranked[:top_n]


def fit_anomaly_scores(feature_vectors: list[dict[str, Any]]) -> list[float]:
    """feature_vectors: one dict per (endpoint, tick) sample for the current
    scenario run, in order. Returns a parallel list of anomaly scores in
    0..1 (higher = more anomalous). Falls back to all-zero if there aren't
    enough samples to fit (e.g. a 1-tick run)."""
    if len(feature_vectors) < 8:
        return [0.0] * len(feature_vectors)

    X = np.array([[fv.get(k, 0.0) for k in FEATURE_KEYS] for fv in feature_vectors])
    model = IsolationForest(n_estimators=150, contamination="auto", random_state=42)
    model.fit(X)
    # decision_function: higher = more normal. Flip and min-max normalize to
    # 0..1 so it reads the same direction as the risk score.
    raw = -model.decision_function(X)
    lo, hi = raw.min(), raw.max()
    if hi - lo < 1e-9:
        return [0.0] * len(feature_vectors)
    return [round(float((v - lo) / (hi - lo)), 3) for v in raw]
