"""SafeAttackSimulator — a benign driver that reproduces a ransomware
behaviour profile against the synthetic corpus and emits real telemetry.

It never imports os, subprocess, or the filesystem. "Encrypting a file" is
`corpus.encrypt_batch(n)` incrementing a counter; "suspending the process"
is a boolean this loop checks. Everything it emits, though — the process
spawns, the rename+entropy events, the shadow-copy deletion, the C2 beacon —
is the same event shape a real ETW/Sysmon collector would produce, so the
detector downstream is doing real work.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any, Literal

from .corpus import FileCorpus

Profile = Literal["NORMAL", "SUSPICIOUS", "RANSOMWARE"]
State = Literal["running", "suspended", "terminated", "done"]

_KNOWN_BAD_IPS = ["185.220.101.45", "45.155.205.171", "194.165.16.75"]
_CIPHERTEXT = (7.94, 7.999)
_RANSOM_EXT = ".ryxlock"

# files rewritten per tick once encryption is underway (ramps up as the
# encryptor spins up threads), by profile
_ENCRYPT_RAMP = [180, 420, 900, 1500, 2100, 2600, 3000, 3200]


class SafeAttackSimulator:
    def __init__(self, profile: Profile, corpus: FileCorpus, seed: int = 7,
                 sim_tick_seconds: int = 4):
        self.profile = profile
        self.corpus = corpus
        self.rng = random.Random(seed)
        self.sim_tick_seconds = sim_tick_seconds
        self.base = datetime(2026, 1, 1, 10, 41, 3)
        self.state: State = "running"
        self.suspended = False
        self.pid = self.rng.randint(4000, 60000)
        self.image = {
            "NORMAL": "OFFICESYNC.EXE",
            "SUSPICIOUS": "backup_runner.exe",
            "RANSOMWARE": "svchost_stage.exe",
        }[profile]
        self.files_touched = 0
        self._encrypt_started_tick: int | None = None

    # ------------------------------------------------------------------ #

    def ts(self, tick: int) -> str:
        return (self.base + timedelta(seconds=tick * self.sim_tick_seconds)).isoformat(timespec="seconds")

    def suspend(self) -> None:
        self.suspended = True
        self.state = "terminated"

    def _file(self, tick: int, op: str, ext: str, *, new_ext: str | None = None,
              entropy: float | None = None) -> dict[str, Any]:
        path = self.corpus.sample_path(self.rng, ext)
        ev: dict[str, Any] = {
            "type": "file", "op": op, "path": path, "ext": ext,
            "size_bytes": self.rng.randint(12_000, 3_000_000),
            "entropy": entropy if entropy is not None else round(self.rng.uniform(3.4, 5.6), 2),
            "ts": self.ts(tick),
        }
        if new_ext:
            ev["new_path"] = path + new_ext
            ev["new_ext"] = new_ext
        return ev

    def _proc(self, tick: int, image: str, parent: str, cmdline: str,
              indicators: list[str] | None = None) -> dict[str, Any]:
        return {
            "type": "process", "action": "spawn",
            "pid": self.rng.randint(2000, 60000), "ppid": self.pid,
            "image": image, "parent_image": parent, "cmdline": cmdline,
            "suspicious_indicators": indicators or [], "ts": self.ts(tick),
        }

    def _net(self, tick: int, ip: str, port: int, reputation: str, bytes_out: int) -> dict[str, Any]:
        return {
            "type": "network", "direction": "outbound", "dest_ip": ip, "dest_port": port,
            "is_external": True, "reputation": reputation, "bytes_out": bytes_out,
            "ts": self.ts(tick),
        }

    def _priv(self, tick: int, action: str, detail: str) -> dict[str, Any]:
        return {"type": "privilege", "action": action, "detail": detail, "ts": self.ts(tick)}

    # ------------------------------------------------------------------ #

    def step(self, tick: int) -> list[dict[str, Any]]:
        """Advance the attack one tick and return the telemetry it produced.
        A no-op once suspended / terminated / done."""
        if self.suspended or self.state in ("terminated", "done"):
            return []
        if self.profile == "NORMAL":
            return self._step_normal(tick)
        if self.profile == "SUSPICIOUS":
            return self._step_suspicious(tick)
        return self._step_ransomware(tick)

    # --- profiles ----------------------------------------------------- #

    def _step_normal(self, tick: int) -> list[dict]:
        out: list[dict] = []
        if self.rng.random() < 0.6:
            out.append(self._file(tick, "modify", self.rng.choice([".docx", ".xlsx", ".pdf"])))
        if tick == 1:
            out.append(self._proc(tick, "WINWORD.EXE", "explorer.exe", "(user launched)"))
        if self.rng.random() < 0.25:
            out.append(self._net(tick, "13.107.42.14", 443, "clean", self.rng.randint(2_000, 40_000)))
        return out

    def _step_suspicious(self, tick: int) -> list[dict]:
        """Nightly backup job: heavy read + create rate, one unsigned helper,
        no rename convergence, no entropy flip, no recovery inhibition, no
        C2. High churn, zero tradecraft — the false-positive control."""
        out: list[dict] = []
        if tick == 0:
            out.append(self._proc(tick, "backup_runner.exe", "services.exe",
                                  "backup_runner.exe /target \\\\backup-01\\nightly",
                                  indicators=["unsigned_binary"]))
        for _ in range(self.rng.randint(14, 26)):
            out.append(self._file(tick, "read", self.rng.choice([".docx", ".xlsx", ".pdf"])))
        for _ in range(self.rng.randint(6, 12)):
            out.append(self._file(tick, "create", ".bkf", entropy=round(self.rng.uniform(7.5, 7.9), 2)))
        self.files_touched += 8
        if tick >= 8:
            self.state = "done"
        return out

    def _step_ransomware(self, tick: int) -> list[dict]:
        out: list[dict] = []

        # t0-1: initial access — macro-spawned encoded PowerShell + first beacon
        if tick == 0:
            out.append(self._proc(tick, "powershell.exe", "WINWORD.EXE",
                                  "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A...",
                                  indicators=["encoded_command", "spawned_from_office_macro"]))
            out.append(self._net(tick, self.rng.choice(_KNOWN_BAD_IPS), 443, "malicious",
                                 self.rng.randint(800, 3000)))
        if tick == 1:
            out.append(self._file(tick, "create", ".exe", entropy=6.9))
            out.append(self._net(tick, self.rng.choice(_KNOWN_BAD_IPS), 443, "malicious",
                                 self.rng.randint(1_000, 4_000)))

        # t2: recovery inhibition + privilege escalation (right before encryption)
        if tick == 2:
            out.append(self._proc(tick, "vssadmin.exe", "cmd.exe",
                                  "vssadmin.exe delete shadows /all /quiet",
                                  indicators=["shadow_copy_deletion", "known_ransomware_tool"]))
            out.append(self._priv(tick, "shadow_copy_delete", "All volume shadow copies deleted via vssadmin"))
            out.append(self._proc(tick, "bcdedit.exe", "cmd.exe",
                                  "bcdedit.exe /set {default} recoveryenabled No",
                                  indicators=["disables_recovery"]))
        if tick == 3:
            out.append(self._priv(tick, "token_elevation",
                                  f"{self.corpus.user} process token elevated to SYSTEM via named-pipe impersonation"))

        # t3+: mass encryption — real corpus mutation + a sample of rename events
        if tick >= 3 and self.corpus.remaining > 0:
            if self._encrypt_started_tick is None:
                self._encrypt_started_tick = tick
            ramp_i = min(tick - self._encrypt_started_tick, len(_ENCRYPT_RAMP) - 1)
            target = _ENCRYPT_RAMP[ramp_i] + self.rng.randint(-120, 120)
            applied = self.corpus.encrypt_batch(max(50, target))
            self.files_touched += applied
            # emit a representative sample of the operations (not one event
            # per file — a real collector samples too): the encryptor rewrites
            # each file in place (modify, ciphertext entropy) then renames it
            # onto the shared extension.
            sample = min(applied, self.rng.randint(22, 34))
            for _ in range(sample):
                src = self.rng.choices(list(self.corpus.ext_mix),
                                       weights=list(self.corpus.ext_mix.values()))[0]
                out.append(self._file(tick, "modify", src,
                                      entropy=round(self.rng.uniform(*_CIPHERTEXT), 3)))
                out.append(self._file(tick, "rename", src, new_ext=_RANSOM_EXT,
                                      entropy=round(self.rng.uniform(*_CIPHERTEXT), 3)))
            out.append(self._net(tick, self.rng.choice(_KNOWN_BAD_IPS), 443, "malicious",
                                 self.rng.randint(300_000, 1_600_000)))
            if tick == 5:
                out.append(self._file(tick, "create", ".txt", entropy=4.1,
                                      new_ext=None))
                out[-1]["path"] = out[-1]["path"].rsplit("\\", 1)[0] + "\\README_RESTORE_FILES.txt"

        if self.corpus.remaining == 0:
            self.state = "done"
        return out
