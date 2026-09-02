"""Feature extraction — turns raw telemetry events into the per-endpoint,
per-tick behavioral signals the risk engine and detector actually score.

Every feature here is something a real EDR/DFIR analyst already looks at
(file write rate, extension churn, entropy of newly-written files, privilege
events, external connection ratio) — no black-box embeddings, so every number
on the dashboard traces back to a concrete, explainable observation.

Uses a trailing rolling window (default 3 ticks = 90s) rather than a single
tick, so a single noisy tick can't flip the score — this is the primary
false-positive control alongside the risk engine's own thresholds.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

WINDOW_TICKS = 6

# What a normal endpoint's rolling window looks like — used to normalize raw
# counts into 0..1 anomaly-relevant ratios. These are deliberately generous
# (twice a genuinely busy normal endpoint) so ordinary bursts of user activity
# don't get flagged; see risk_engine.py LEVELS for how the resulting score
# maps to low/medium/high/critical.
BASELINE = {
    "file_mod_rate": 2.0,        # file writes per tick
    "file_rename_rate": 0.3,
    "new_ext_convergence": 0.0,  # renames converging on one shared new extension
    "entropy_flip_rate": 0.0,    # low-entropy files that suddenly read as ciphertext
    "process_spawn_rate": 0.6,
    "suspicious_process_rate": 0.0,
    "privilege_event_rate": 0.0,
    "network_conn_rate": 0.4,
    "malicious_conn_rate": 0.0,
}


def _window_events(history: list[dict], endpoint_id: str, upto_tick: int) -> list[dict]:
    """All events for one endpoint across the trailing WINDOW_TICKS ticks,
    ending at (and including) upto_tick."""
    lo = max(0, upto_tick - WINDOW_TICKS + 1)
    events: list[dict] = []
    for tick_entry in history[lo:upto_tick + 1]:
        events += tick_entry["events_by_endpoint"].get(endpoint_id, [])
    return events


def extract_features(history: list[dict], endpoint_id: str, upto_tick: int) -> dict[str, Any]:
    """Computes the rolling-window feature vector for one endpoint as of
    upto_tick, plus a handful of human-readable evidence strings used
    directly in alerts/copilot explanations."""
    events = _window_events(history, endpoint_id, upto_tick)
    n_windows = min(upto_tick + 1, WINDOW_TICKS)

    file_events = [e for e in events if e["type"] == "file"]
    modifies = [e for e in file_events if e["op"] == "modify"]
    creates = [e for e in file_events if e["op"] == "create"]
    renames = [e for e in file_events if e["op"] == "rename"]
    deletes = [e for e in file_events if e["op"] == "delete"]

    process_events = [e for e in events if e["type"] == "process"]
    suspicious_procs = [e for e in process_events if e.get("suspicious_indicators")]

    privilege_events = [e for e in events if e["type"] == "privilege"]

    # Recovery inhibition — shadow-copy deletion / recovery disabling. Called
    # out on its own because it is a near-unambiguous ransomware precursor
    # (there is no legitimate bulk reason to destroy every restore point):
    # alerts.py uses it to raise an *early* warning during the staging phase,
    # before mass encryption has pushed the weighted score over threshold.
    recovery_inhibition = any(
        e.get("action") in ("shadow_copy_delete",) for e in privilege_events
    ) or any(
        {"shadow_copy_deletion", "disables_recovery"} & set(e.get("suspicious_indicators", []))
        for e in suspicious_procs
    )

    network_events = [e for e in events if e["type"] == "network"]
    malicious_conns = [e for e in network_events if e.get("reputation") == "malicious"]
    external_conns = [e for e in network_events if e.get("is_external")]

    # New-extension convergence: renames landing on the same unfamiliar
    # extension are a single actor doing something systematic — format
    # independent, so it works regardless of what kind of file was touched.
    new_exts = [e["new_ext"] for e in renames if e.get("new_ext")]
    convergence = 0.0
    if renames:
        top_ext_count = max((new_exts.count(x) for x in set(new_exts)), default=0)
        convergence = top_ext_count / len(renames)

    # Entropy flip: a file whose extension normally reads low-entropy
    # (plaintext/uncompressed) now reads at ciphertext-level entropy. Skips
    # already-compressed formats (docx/pdf/jpg/...) on purpose — those sit
    # near ciphertext entropy even when legitimately saved, so they're not
    # usable evidence on their own (see telemetry.py EXT_BASELINE_ENTROPY).
    from .telemetry import EXT_BASELINE_ENTROPY  # local import: avoids a cycle at module load

    def _is_flip(e: dict) -> bool:
        ext = e.get("ext")
        baseline = EXT_BASELINE_ENTROPY.get(ext)
        return bool(baseline and baseline[1] < 6.0 and e.get("entropy", 0) >= 7.5)

    entropy_flips = [e for e in renames + modifies if _is_flip(e)]

    touched_paths = {e["path"] for e in file_events}
    unique_extensions = {e["ext"] for e in file_events}

    feat = {
        "file_mod_rate": round((len(modifies) + len(creates)) / n_windows, 2),
        "file_rename_rate": round(len(renames) / n_windows, 2),
        "file_delete_rate": round(len(deletes) / n_windows, 2),
        "unique_extensions_touched": len(unique_extensions),
        "files_touched": len(touched_paths),
        "new_ext_convergence": round(convergence, 2),
        "entropy_flip_rate": round(len(entropy_flips) / n_windows, 2),
        "process_spawn_rate": round(len(process_events) / n_windows, 2),
        "suspicious_process_rate": round(len(suspicious_procs) / n_windows, 2),
        "privilege_event_rate": round(len(privilege_events) / n_windows, 2),
        "network_conn_rate": round(len(network_events) / n_windows, 2),
        "malicious_conn_rate": round(len(malicious_conns) / n_windows, 2),
        "external_conn_ratio": round(len(external_conns) / len(network_events), 2) if network_events else 0.0,
        "recovery_inhibition": recovery_inhibition,
    }

    evidence: list[str] = []
    if suspicious_procs:
        p = suspicious_procs[-1]
        evidence.append(f"{p['image']} spawned from {p['parent_image']} — {', '.join(p['suspicious_indicators'])} (`{p['cmdline'][:70]}`)")
    if privilege_events:
        pv = privilege_events[-1]
        evidence.append(f"{pv['action']}: {pv['detail']}")
    if renames and convergence > 0.5:
        evidence.append(f"{len(renames)} files renamed to `{new_exts[0] if new_exts else '?'}` in the last {n_windows * 30}s")
    if entropy_flips:
        evidence.append(f"{len(entropy_flips)} previously plaintext files now read at ciphertext-level entropy (>=7.5 bits/byte)")
    if malicious_conns:
        c = malicious_conns[-1]
        evidence.append(f"Outbound connection to {c['dest_ip']}:{c['dest_port']} — reputation: malicious")

    feat["evidence"] = evidence
    feat["raw_events_in_window"] = len(events)
    return feat
