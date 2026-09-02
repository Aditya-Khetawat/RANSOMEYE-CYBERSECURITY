"""Synthetic file corpus for the Attack Lab.

Represented as counters plus a small pool of realistic file paths — never
real files. `encrypted` is the genuine running count of files the simulator
has rewritten; it is what the "files affected / files protected" numbers are
measured from.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

# plaintext-ish types the entropy-flip signal can actually see (mirrors the
# sub-6.0 entries of telemetry.EXT_BASELINE_ENTROPY)
_PLAINTEXT_EXTS = [".docx", ".xlsx", ".pdf", ".txt", ".csv", ".pptx", ".sql", ".xml"]
_DIRS = [
    r"C:\Users\{u}\Documents", r"C:\Users\{u}\Desktop",
    r"C:\Users\{u}\Documents\Clients", r"C:\Users\{u}\Documents\2026",
    r"\\fileserver\finance\{u}", r"C:\Users\{u}\Downloads",
]
_NAMES = ["Q4_report", "invoice", "payroll", "contract", "budget", "forecast",
          "audit", "statement", "ledger", "proposal", "NDA", "tax_return"]


@dataclass
class FileCorpus:
    user: str = "d.chen"
    total: int = 50_000
    encrypted: int = 0
    ext_mix: dict[str, float] = field(default_factory=lambda: {
        ".docx": 0.24, ".xlsx": 0.22, ".pdf": 0.20, ".csv": 0.10,
        ".pptx": 0.08, ".txt": 0.06, ".sql": 0.05, ".xml": 0.05,
    })

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.encrypted)

    @property
    def pct_encrypted(self) -> float:
        return round(self.encrypted / self.total, 4) if self.total else 0.0

    def sample_path(self, rng: random.Random, ext: str | None = None) -> str:
        e = ext or rng.choices(list(self.ext_mix), weights=list(self.ext_mix.values()))[0]
        d = rng.choice(_DIRS).format(u=self.user)
        return f"{d}\\{rng.choice(_NAMES)}_{rng.randint(1000, 9999)}{e}"

    def encrypt_batch(self, n: int) -> int:
        """Rewrite up to `n` more files. Returns how many were actually
        rewritten (capped at what's left)."""
        applied = min(n, self.remaining)
        self.encrypted += applied
        return applied
