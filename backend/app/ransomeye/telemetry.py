"""Synthetic host-telemetry generator — this detection engine's escape hatch.

This ransomware-detection engine needs file-system, process, network and
privilege telemetry the way the alert correlation engine needs a stream of
monitoring alerts. Real telemetry means a kernel driver / ETW consumer /
eBPF probe on every endpoint — out of scope for a hackathon prototype and
unsafe to fake with an actual encryptor.

Instead this module generates a realistic, fully-labelled telemetry stream for
a small fleet of endpoints, the same way data/synthetic_alert_generator.py
generates alert floods for the alert correlation engine: deterministic under
a seed, built from concrete named templates (real tool names, real cmdlines,
real ransomware tradecraft), so every event in a demo can be defended under
judge questioning.

The detection pipeline (features.py / detector.py / risk_engine.py) reads
*only* the emitted events below — it never reads `stage` or the scenario key,
same separation the alert correlation engine keeps between its generator's
ground_truth and the clustering pipeline.

Swap-in point for real telemetry: replace `run_scenario`'s call into this
module with a real collector (Sysmon/ETW on Windows, auditd/eBPF on Linux)
that emits the same four event shapes (file/process/network/privilege) on the
same tick cadence — nothing downstream of this file needs to change.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any

TICK_SECONDS = 30

FLEET: list[dict[str, str]] = [
    {"id": "WKS-NA-118", "hostname": "wks-na-118.corp.local", "ip": "10.10.6.118",
     "os": "Windows 11 Pro", "user": "j.martinez", "department": "Legal"},
    {"id": "WKS-EMEA-014", "hostname": "wks-emea-014.corp.local", "ip": "10.40.12.14",
     "os": "Windows 11 Pro", "user": "h.becker", "department": "Finance"},
    {"id": "WKS-NA-207", "hostname": "wks-na-207.corp.local", "ip": "10.10.6.207",
     "os": "Windows 10 Enterprise", "user": "r.iyer", "department": "Sales"},
    {"id": "FILESRV-02", "hostname": "filesrv-02.corp.local", "ip": "10.10.1.12",
     "os": "Windows Server 2019", "user": "svc-fileshare", "department": "IT"},
    {"id": "WKS-APAC-041", "hostname": "wks-apac-041.corp.local", "ip": "10.60.3.41",
     "os": "Windows 10 Pro", "user": "m.tanaka", "department": "Engineering"},
    {"id": "WKS-NA-063", "hostname": "wks-na-063.corp.local", "ip": "10.10.6.63",
     "os": "Windows 11 Pro", "user": "a.khan", "department": "HR"},
]

TARGET_ENDPOINT_ID = "WKS-NA-118"

# extension -> typical entropy range for a legitimately-saved file of that
# type. Office/zip/image/pdf formats are already internally compressed, so
# they sit almost as high as ciphertext — the detector cannot use raw entropy
# alone (see risk_engine.py's low_entropy_flip signal for how this is
# handled defensibly).
EXT_BASELINE_ENTROPY: dict[str, tuple[float, float]] = {
    ".docx": (7.75, 7.97), ".xlsx": (7.75, 7.97), ".pptx": (7.75, 7.97),
    ".pdf": (7.6, 7.9), ".jpg": (7.7, 7.95), ".png": (7.6, 7.9), ".zip": (7.8, 7.99),
    ".txt": (3.2, 4.6), ".csv": (3.0, 4.4), ".log": (3.4, 4.8),
    ".sql": (3.6, 5.0), ".xml": (3.8, 5.2), ".ini": (3.0, 4.0), ".bmp": (2.0, 3.5),
}
NORMAL_EXTENSIONS = list(EXT_BASELINE_ENTROPY)
CIPHERTEXT_ENTROPY = (7.94, 7.999)
RANSOM_EXTENSIONS = [".ryxlock", ".enc_v3", ".locked"]

DIRS = [
    r"C:\Users\{user}\Documents", r"C:\Users\{user}\Desktop",
    r"C:\Users\{user}\Documents\Projects", r"C:\Users\{user}\Downloads",
    r"\\filesrv-02\shared\{dept}",
]

CLOUD_IPS = ["52.96.28.14", "13.107.42.14", "142.250.72.14", "104.16.85.20"]
KNOWN_BAD_IPS = ["185.220.101.45", "45.155.205.171", "194.165.16.75"]


def _ts(base: datetime, tick: int) -> str:
    return (base + timedelta(seconds=tick * TICK_SECONDS)).isoformat(timespec="seconds")


def _dir_for(ep: dict) -> str:
    return random.choice(DIRS).format(user=ep["user"], dept=ep["department"].lower())


def _file_event(ep: dict, base: datetime, tick: int, op: str, ext: str | None = None,
                 new_ext: str | None = None, entropy: float | None = None,
                 path_hint: str | None = None) -> dict:
    ext = ext or random.choice(NORMAL_EXTENSIONS)
    if entropy is None:
        lo, hi = EXT_BASELINE_ENTROPY.get(ext, (4.0, 6.0))
        entropy = round(random.uniform(lo, hi), 2)
    name = path_hint or f"{random.choice(['report', 'invoice', 'notes', 'budget', 'contract', 'photo', 'export'])}_{random.randint(100, 999)}"
    path = f"{_dir_for(ep)}\\{name}{ext}"
    event: dict[str, Any] = {
        "type": "file", "op": op, "path": path, "ext": ext,
        "size_bytes": random.randint(8_000, 4_000_000), "entropy": entropy,
        "ts": _ts(base, tick),
    }
    if new_ext:
        event["new_path"] = path.rsplit(ext, 1)[0] + ext + new_ext
        event["new_ext"] = new_ext
    return event


def _process_event(ep: dict, base: datetime, tick: int, image: str, parent_image: str,
                    cmdline: str, indicators: list[str] | None = None) -> dict:
    return {
        "type": "process", "action": "spawn", "pid": random.randint(2000, 60000),
        "ppid": random.randint(500, 2000), "image": image, "parent_image": parent_image,
        "cmdline": cmdline, "suspicious_indicators": indicators or [], "ts": _ts(base, tick),
    }


def _network_event(ep: dict, base: datetime, tick: int, dest_ip: str, dest_port: int,
                    reputation: str, bytes_out: int) -> dict:
    return {
        "type": "network", "direction": "outbound", "dest_ip": dest_ip, "dest_port": dest_port,
        "is_external": True, "reputation": reputation, "bytes_out": bytes_out,
        "ts": _ts(base, tick),
    }


def _privilege_event(ep: dict, base: datetime, tick: int, action: str, detail: str) -> dict:
    return {"type": "privilege", "action": action, "detail": detail, "ts": _ts(base, tick)}


def _baseline_noise(ep: dict, base: datetime, tick: int) -> list[dict]:
    """Light, unremarkable background activity every endpoint in the fleet
    produces — office saves, a browser/Office process spawning, a cloud sync
    connection. This is what "normal" looks like to the detector, and what
    keeps the Live Threat Feed populated with real (non-alerting) traffic."""
    events: list[dict] = []
    if random.random() < 0.5:
        events.append(_file_event(ep, base, tick, "modify"))
    if random.random() < 0.15:
        events.append(_process_event(
            ep, base, tick,
            image=random.choice(["WINWORD.EXE", "EXCEL.EXE", "chrome.exe", "outlook.exe", "Teams.exe"]),
            parent_image="explorer.exe", cmdline="(user launched)",
        ))
    if random.random() < 0.2:
        events.append(_network_event(ep, base, tick, dest_ip=random.choice(CLOUD_IPS),
                                     dest_port=443, reputation="clean",
                                     bytes_out=random.randint(2_000, 80_000)))
    return events


def _suspicious_stage_events(ep: dict, base: datetime, tick: int, local_tick: int) -> list[dict]:
    """SUSPICIOUS_ACTIVITY target: one odd script + one unusual connection +
    a batch of extra file writes (a backup/archiving job is the cover story).
    Deliberately stops well short of the ransomware tradecraft below (no
    shadow-copy deletion, no mass rename, no malicious-reputation contact,
    no entropy spike) — this is the false-positive control case: anomalous,
    sometimes loudly so, but not an attack, and the detector should say so
    regardless of how noisy the run gets.

    Intensity varies per seed (2-14 files/tick, not a fixed narrow band) —
    a false-positive control that is only ever quiet would be an easy test,
    not a real one; some seeds here get genuinely close to looking like a
    bulk file operation."""
    events: list[dict] = []
    if local_tick == 2:
        events.append(_process_event(
            ep, base, tick, image="powershell.exe", parent_image="explorer.exe",
            cmdline="powershell.exe -NoProfile -Command Get-Process | Export-Csv procs.csv",
            indicators=["unsigned_script"],
        ))
    if local_tick in (3, 4, 5):
        for _ in range(random.randint(2, 14)):
            events.append(_file_event(ep, base, tick, "modify"))
    if local_tick == 4:
        events.append(_network_event(ep, base, tick, dest_ip="203.0.113.44", dest_port=8080,
                                     reputation="unknown", bytes_out=random.randint(5_000, 60_000)))
    return events


# (local_tick, builder) — the ransomware kill chain on the target endpoint.
# Mirrors the alert correlation engine's cascade-of-tuples style in
# synthetic_alert_generator.py.
def _ransomware_stage_events(
    ep: dict, base: datetime, tick: int, local_tick: int, skip_defense_evasion: bool
) -> list[dict]:
    """skip_defense_evasion: some real ransomware skips shadow-copy deletion
    and recovery-disabling entirely to encrypt faster ("smash and grab"
    rather than methodical defense evasion) — modeled here so the evaluation
    actually tests whether detection holds on the *remaining* signals (mass
    rename, entropy flip, C2 contact) alone, rather than only ever testing
    the full seven-signal case."""
    events: list[dict] = []

    # Stage 1 (t=2-3): initial access — macro-spawned PowerShell, encoded
    # command, staged payload, beacon to a C2 IP.
    if local_tick == 2:
        events.append(_process_event(
            ep, base, tick, image="powershell.exe", parent_image="WINWORD.EXE",
            cmdline="powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw...",
            indicators=["encoded_command", "spawned_from_office_macro"],
        ))
        events.append(_network_event(ep, base, tick, dest_ip=random.choice(KNOWN_BAD_IPS),
                                     dest_port=4444, reputation="malicious",
                                     bytes_out=random.randint(1_000, 4_000)))
    if local_tick == 3:
        events.append(_file_event(ep, base, tick, "create", ext=".exe", entropy=6.8,
                                  path_hint="svchost_upd"))

    # Stage 2 (t=6-7): discovery + defense evasion — shadow copy deletion,
    # recovery disabled, privilege escalation attempt. Placed right where
    # mass file activity begins (not a separate earlier dwell period) —
    # real ransomware disables recovery immediately before/as it starts
    # encrypting, so the two signals corroborate each other in the same
    # rolling window rather than aging out independently. Skipped entirely
    # for the smash-and-grab variant (see skip_defense_evasion above).
    if not skip_defense_evasion and local_tick == 6:
        events.append(_process_event(
            ep, base, tick, image="vssadmin.exe", parent_image="cmd.exe",
            cmdline="vssadmin.exe delete shadows /all /quiet",
            indicators=["shadow_copy_deletion", "known_ransomware_tool"],
        ))
        events.append(_privilege_event(ep, base, tick, "shadow_copy_delete",
                                       "All volume shadow copies deleted via vssadmin"))
    if not skip_defense_evasion and local_tick == 7:
        events.append(_process_event(
            ep, base, tick, image="bcdedit.exe", parent_image="cmd.exe",
            cmdline="bcdedit.exe /set {default} recoveryenabled No",
            indicators=["disables_recovery", "known_ransomware_tool"],
        ))
        events.append(_privilege_event(ep, base, tick, "token_elevation",
                                       f"{ep['user']} process token elevated to SYSTEM via named-pipe impersonation"))

    # Stage 3 (t=7-13): rapid mass file activity — dozens of files per tick
    # across every directory, touching every extension on the endpoint.
    # Intensity varies per seed: some runs are a loud, fast smash-and-grab,
    # others a quieter/slower encryptor throttling itself to stay under
    # naive rate-limit rules — the detector needs to catch both, not just
    # the loud case, so the range spans a real stealthy-to-loud spectrum.
    if 7 <= local_tick <= 13:
        n = random.randint(8, 40)
        for _ in range(n):
            events.append(_file_event(ep, base, tick, "modify", ext=random.choice(NORMAL_EXTENSIONS)))

    # Stage 4 (t=9-14): entropy spike + mass rename to a shared, unfamiliar
    # extension — the format-independent "encryption in progress" tell.
    if 9 <= local_tick <= 14:
        n = random.randint(6, 32)
        ransom_ext = RANSOM_EXTENSIONS[0]
        for _ in range(n):
            src_ext = random.choice(NORMAL_EXTENSIONS)
            cipher_entropy = round(random.uniform(*CIPHERTEXT_ENTROPY), 3)
            events.append(_file_event(ep, base, tick, "rename", ext=src_ext,
                                      new_ext=ransom_ext, entropy=cipher_entropy))
        if local_tick == 14:
            events.append(_file_event(ep, base, tick, "create", ext=".txt", entropy=4.1,
                                      path_hint="README_DECRYPT"))

    # Stage 5 (t=10-15): sustained beacon / possible exfil-before-encrypt.
    if 10 <= local_tick <= 15:
        events.append(_network_event(ep, base, tick, dest_ip=random.choice(KNOWN_BAD_IPS),
                                     dest_port=443, reputation="malicious",
                                     bytes_out=random.randint(400_000, 2_000_000)))

    return events


def generate_scenario(scenario: str, seed: int | None = None) -> dict[str, Any]:
    """Returns {"endpoints": [...], "target_endpoint_id": ..., "ticks": [...]}
    where ticks[i] = {"tick": i, "ts": ..., "events_by_endpoint": {ep_id: [events]}}.
    """
    if seed is not None:
        random.seed(seed)
    base = datetime.now().replace(microsecond=0)

    # Decided once per run, not per tick: roughly a third of ransomware runs
    # skip defense evasion entirely (see _ransomware_stage_events) — this is
    # what the evaluation page's detection rate is actually measured across,
    # not just the loud full-kill-chain case.
    skip_defense_evasion = scenario == "RANSOMWARE_ATTACK" and random.random() < 0.35

    n_ticks = {"NORMAL_ACTIVITY": 10, "SUSPICIOUS_ACTIVITY": 10, "RANSOMWARE_ATTACK": 20}[scenario]
    ticks: list[dict] = []

    for t in range(n_ticks):
        events_by_endpoint: dict[str, list[dict]] = {}
        for ep in FLEET:
            evs = list(_baseline_noise(ep, base, t))
            if ep["id"] == TARGET_ENDPOINT_ID:
                if scenario == "SUSPICIOUS_ACTIVITY":
                    evs += _suspicious_stage_events(ep, base, t, t)
                elif scenario == "RANSOMWARE_ATTACK":
                    evs += _ransomware_stage_events(ep, base, t, t, skip_defense_evasion)
            events_by_endpoint[ep["id"]] = evs
        ticks.append({"tick": t, "ts": _ts(base, t), "events_by_endpoint": events_by_endpoint})

    return {
        "scenario": scenario,
        "run_id": uuid.uuid4().hex[:10],
        "endpoints": FLEET,
        "target_endpoint_id": TARGET_ENDPOINT_ID if scenario != "NORMAL_ACTIVITY" else None,
        "ticks": ticks,
        "variant": {"skip_defense_evasion": skip_defense_evasion} if scenario == "RANSOMWARE_ATTACK" else None,
    }
