"""Early Warning alert generation — fires (once) when an endpoint's risk
score crosses the "high" threshold, mirroring the alert correlation engine's
automation.py philosophy of a real, dedup'd firing rather than a per-tick
spam of the same warning.

An early warning intentionally fires at "high" (>=60), not only "critical"
(>=85) — the entire point of an *early* warning system is to alert before
the attack is fully unambiguous. SUSPICIOUS_ACTIVITY is calibrated (see
telemetry.py) to stay under 60, which is what proves the threshold isn't
just tripping on any anomaly.
"""

from __future__ import annotations

import uuid
from typing import Any

ALERT_THRESHOLD = 60


def maybe_fire_alert(endpoint: dict, tick: int, ts: str, risk: dict,
                      feat: dict, already_fired: bool) -> dict[str, Any] | None:
    if already_fired or risk["score"] < ALERT_THRESHOLD:
        return None

    top_factor = max(risk["factors"], key=risk["factors"].get)
    top_factor_label = top_factor.replace("_", " ")

    return {
        "id": uuid.uuid4().hex[:10],
        "endpoint_id": endpoint["id"],
        "hostname": endpoint["hostname"],
        "user": endpoint["user"],
        "severity": "critical" if risk["score"] >= 85 else "high",
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "fired_at_tick": tick,
        "timestamp": ts,
        "title": f"Ransomware-like behavior detected on {endpoint['id']}",
        "primary_signal": top_factor_label,
        "contributing_behaviors": risk.get("evidence", []),
        "affected_process": next(
            (e.split(" spawned from")[0] for e in feat.get("evidence", []) if "spawned from" in e),
            None,
        ),
        "recommended_action": (
            f"Isolate {endpoint['id']} immediately and suspend the flagged process — encryption activity in progress."
            if risk["score"] >= 85 else
            f"Escalate {endpoint['id']} to SOC for review and stage containment for approval."
        ),
    }
