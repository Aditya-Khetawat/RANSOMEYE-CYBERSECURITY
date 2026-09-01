"""Defensive Containment — adapted from the alert correlation engine's
playbook.py (app/playbook.py: structured, step-by-step response actions
derived from pipeline output), reshaped into a list of individually
approvable containment actions rather than a linear runbook, because
containment actions here are real (if simulated) state changes, not just
SRE reading material.

Destructive/disruptive actions (suspend process, isolate endpoint, block
network indicator) are generated with requires_approval=True and stay
"pending" until an operator calls the approve endpoint — this prototype never
executes them on its own. Non-destructive actions (preserve telemetry, notify
SOC) are safe to auto-execute immediately, the same way app/automation.py
auto-fires notify actions without a human in the loop.
"""

from __future__ import annotations

import uuid
from typing import Any


def generate_containment_plan(endpoint: dict, risk: dict, feat: dict) -> list[dict[str, Any]]:
    ep_id = endpoint["id"]
    malicious_ips = [e.split("Outbound connection to ")[1].split(" —")[0].split(":")[0]
                     for e in feat.get("evidence", []) if e.startswith("Outbound connection to")]

    actions = [
        {
            "id": uuid.uuid4().hex[:8],
            "action_type": "preserve_telemetry",
            "title": "Preserve telemetry & volatile evidence",
            "description": f"Snapshot process list, open handles, and the last {feat.get('raw_events_in_window', 0)} telemetry events on {ep_id} before any disruptive action, for forensics.",
            "destructive": False,
            "requires_approval": False,
            "status": "executed",
        },
        {
            "id": uuid.uuid4().hex[:8],
            "action_type": "notify_soc",
            "title": "Notify Security Operations Center",
            "description": f"Page on-call SOC analyst: {risk['level'].upper()} ransomware risk ({risk['score']}/100) on {ep_id} ({endpoint['user']}, {endpoint['department']}).",
            "destructive": False,
            "requires_approval": False,
            "status": "executed",
        },
        {
            "id": uuid.uuid4().hex[:8],
            "action_type": "suspend_process",
            "title": "Suspend/terminate suspicious process",
            "description": "Terminate the flagged process tree (e.g. vssadmin.exe, powershell.exe with encoded command) before it can touch further files.",
            "destructive": True,
            "requires_approval": True,
            "status": "pending_approval",
        },
        {
            "id": uuid.uuid4().hex[:8],
            "action_type": "isolate_endpoint",
            "title": f"Isolate {ep_id} from the network",
            "description": f"Move {ep_id} ({endpoint['ip']}) to an isolated VLAN / disable its switch port — stops further encryption and any exfil in progress, while keeping the host powered on for forensics.",
            "destructive": True,
            "requires_approval": True,
            "status": "pending_approval",
        },
    ]

    if malicious_ips or risk["factors"].get("network_abnormality", 0) > 0.2:
        target_ip = malicious_ips[0] if malicious_ips else "the observed C2 host"
        actions.append({
            "id": uuid.uuid4().hex[:8],
            "action_type": "block_indicator",
            "title": f"Block network indicator {target_ip}",
            "description": f"Push a firewall/EDR block rule for {target_ip} across the fleet, not just {ep_id}, in case other endpoints are contacted next.",
            "destructive": True,
            "requires_approval": True,
            "status": "pending_approval",
        })

    return actions


def approve_action(actions: list[dict], action_id: str) -> dict | None:
    for a in actions:
        if a["id"] == action_id:
            if not a["requires_approval"]:
                return a  # already auto-executed, nothing to approve
            a["status"] = "executed"
            return a
    return None
