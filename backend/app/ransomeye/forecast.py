"""Encryption Impact Forecast — adapted from the alert correlation engine's
forecast.py (app/forecast.py's compute_forecast: explainable, deterministic,
+5/+10/+15m horizon), swapping
"blast radius across services" for "files encrypted / risk trajectory on this
endpoint". Same shape: a list of horizon steps plus a plain-language
recommended action and reasoning, consumed by existing chart-friendly UI
patterns.
"""

from __future__ import annotations

from typing import Any

HORIZONS = [5, 10, 15]


def compute_forecast(endpoint: dict, risk_history: list[dict], current_feat: dict) -> dict[str, Any]:
    """risk_history: this endpoint's [{tick, score, files_touched, file_mod_rate}, ...]
    across the run so far, oldest first. Needs >=2 points to derive a trend;
    with fewer, projects flat (honest, not padded with a fabricated slope)."""
    if len(risk_history) < 2:
        current_score = risk_history[-1]["score"] if risk_history else 0
        return {
            "endpoint_id": endpoint["id"],
            "currentRisk": current_score,
            "confidence": 0.4,
            "recommendedImmediateAction": "Continue monitoring — insufficient trend data for a forecast yet.",
            "forecast": [{"minutes": m, "risk": current_score, "estimated_files_encrypted": current_feat.get("files_touched", 0), "confidence": 0.4} for m in HORIZONS],
            "reasoning": ["Not enough ticks observed yet to compute a growth trend."],
        }

    recent = risk_history[-3:] if len(risk_history) >= 3 else risk_history
    score_slope = (recent[-1]["score"] - recent[0]["score"]) / max(len(recent) - 1, 1)
    file_rate_slope = (recent[-1]["file_mod_rate"] - recent[0]["file_mod_rate"]) / max(len(recent) - 1, 1)

    current_score = risk_history[-1]["score"]
    current_files = current_feat.get("files_touched", 0)
    ticks_per_min = 2  # TICK_SECONDS = 30

    steps = []
    for m in HORIZONS:
        n_ticks = m * ticks_per_min
        projected_risk = max(0, min(100, round(current_score + score_slope * n_ticks)))
        rate_now = max(current_feat.get("file_mod_rate", 0.0), 0.0)
        projected_rate = max(rate_now + file_rate_slope * n_ticks, 0.0)
        # trapezoid estimate of files touched between now and horizon m
        added_files = round((rate_now + projected_rate) / 2 * n_ticks)
        confidence = round(max(0.55, 0.92 - 0.02 * m), 2)
        steps.append({
            "minutes": m,
            "risk": projected_risk,
            "estimated_files_encrypted": current_files + added_files,
            "confidence": confidence,
        })

    if current_score >= 85 or score_slope > 3:
        rec_action = f"Isolate {endpoint['id']} from the network immediately — encryption is active and accelerating."
    elif current_score >= 60:
        rec_action = f"Prepare to isolate {endpoint['id']}; escalate to SOC now and stage endpoint isolation for approval."
    elif score_slope > 0.5:
        rec_action = f"Increase monitoring cadence on {endpoint['id']} — risk is trending upward."
    else:
        rec_action = f"No action needed — {endpoint['id']} risk is stable or declining."

    reasoning = [
        f"Risk score moved {'+' if score_slope >= 0 else ''}{round(score_slope, 1)}/tick over the last {len(recent)} ticks.",
        f"File modification rate is {'accelerating' if file_rate_slope > 0 else 'flat or declining'} "
        f"({round(current_feat.get('file_mod_rate', 0), 1)} files/tick currently).",
    ]
    if current_feat.get("evidence"):
        reasoning.append("Latest observed evidence: " + "; ".join(current_feat["evidence"][:2]))

    return {
        "endpoint_id": endpoint["id"],
        "currentRisk": current_score,
        "confidence": round(sum(s["confidence"] for s in steps) / len(steps), 2),
        "recommendedImmediateAction": rec_action,
        "forecast": steps,
        "reasoning": reasoning,
    }
