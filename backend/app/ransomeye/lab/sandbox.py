"""LabSession — one live controlled attack, wired into the real detector.

Each tick: the simulator acts, the telemetry it produced is scored by the
same features.py / risk_engine.py / alerts.py the product uses everywhere
else, and the result is appended to the session history. Containment
genuinely stops the simulator and freezes the counters.
"""

from __future__ import annotations

from typing import Any

import uuid

from ..alerts import maybe_fire_alert
from ..detector import fit_anomaly_scores
from ..features import BASELINE, extract_features
from ..risk_engine import score_risk
from .attacker import Profile, SafeAttackSimulator
from .corpus import FileCorpus
from .counterfactual import run_counterfactual

_ENDPOINT = {
    "id": "FINANCE-WS-042", "hostname": "finance-ws-042.corp.local",
    "user": "d.chen", "department": "Finance", "ip": "10.20.7.42",
    "os": "Windows 11 Pro",
}
_CATASTROPHE_PCT = 0.9  # "too late" = this fraction of the corpus encrypted


def _early_warning(tick: int, ts: str, risk: dict, feat: dict) -> dict | None:
    """Precursor early warning — fires during the staging phase, before mass
    encryption has driven the weighted score past the standard threshold,
    when recovery inhibition is corroborated by suspicious process or
    known-bad network activity in the same window. This is the whole point
    of an *early* warning system: the shadow-copy deletion is the tell, not
    the encryption that follows it.
    """
    if not feat.get("recovery_inhibition"):
        return None
    if risk["score"] < 40:
        return None
    if feat.get("malicious_conn_rate", 0) <= 0 and feat.get("suspicious_process_rate", 0) <= 0:
        return None
    return {
        "id": uuid.uuid4().hex[:10],
        "endpoint_id": _ENDPOINT["id"], "hostname": _ENDPOINT["hostname"], "user": _ENDPOINT["user"],
        "severity": "high", "risk_score": risk["score"], "risk_level": risk["level"],
        "fired_at_tick": tick, "timestamp": ts,
        "title": f"Ransomware staging detected on {_ENDPOINT['id']}",
        "primary_signal": "recovery inhibition",
        "contributing_behaviors": risk.get("evidence", []),
        "affected_process": next(
            (e.split(" spawned from")[0] for e in feat.get("evidence", []) if "spawned from" in e), None),
        "recommended_action": f"Isolate {_ENDPOINT['id']} and suspend the flagged process now — encryption has not started yet.",
        "early_warning": True,
    }


class LabSession:
    def __init__(self, profile: Profile, seed: int = 7, corpus_size: int = 50_000,
                 sim_tick_seconds: int = 4):
        self.profile = profile
        self.seed = seed
        self.sim_tick_seconds = sim_tick_seconds
        self.corpus = FileCorpus(user=_ENDPOINT["user"], total=corpus_size)
        self.sim = SafeAttackSimulator(profile, self.corpus, seed=seed,
                                       sim_tick_seconds=sim_tick_seconds)
        self.tick = -1
        self.history: list[dict] = []          # [{tick, ts, events_by_endpoint, feat, risk, alert}]
        self.alert: dict | None = None
        self.contained = False
        self.contain_tick: int | None = None
        self.contain_ts: str | None = None
        self.forensic: dict | None = None
        self._frozen_signals: list[dict] | None = None
        self._frozen_evidence: list[str] | None = None
        self.counterfactual = run_counterfactual(profile, seed, corpus_size, sim_tick_seconds)

    # ------------------------------------------------------------------ #

    @property
    def status(self) -> str:
        if self.contained:
            return "contained"
        if self.sim.state == "done":
            return "completed"
        return "running"

    def advance(self) -> None:
        if self.contained or self.sim.state in ("done", "terminated"):
            # keep clock moving a little so a finished run still reads live,
            # but nothing changes
            return
        self.tick += 1
        t = self.tick
        events = self.sim.step(t)
        self.history.append({
            "tick": t, "ts": self.sim.ts(t),
            "events_by_endpoint": {_ENDPOINT["id"]: events},
        })
        feat = extract_features(self.history, _ENDPOINT["id"], t)

        ml = None
        if len(self.history) >= 8:
            vecs = [extract_features(self.history, _ENDPOINT["id"], h["tick"]) for h in self.history]
            ml = fit_anomaly_scores(vecs)[-1]

        risk = score_risk(feat, ml_anomaly_score=ml)
        self.history[-1]["feat"] = feat
        self.history[-1]["risk"] = risk

        if self.alert is None:
            fired = maybe_fire_alert(_ENDPOINT, t, self.sim.ts(t), risk, feat, already_fired=False)
            if not fired:
                fired = _early_warning(t, self.sim.ts(t), risk, feat)
            if fired:
                self.alert = fired

    def contain(self) -> None:
        if self.contained:
            return
        self.sim.suspend()
        self.contained = True
        self.contain_tick = self.tick
        self.contain_ts = self.sim.ts(self.tick)
        cur = self.history[-1] if self.history else {}
        cur_feat = cur.get("feat", {k: 0.0 for k in BASELINE})
        cur_risk = cur.get("risk", {})
        # Freeze the evidence picture as it stood at containment — the rolling
        # window would otherwise let the tradecraft signals age out and make
        # the "why we stopped it" panel misleadingly quiet a few ticks later.
        self._frozen_signals = self._signals(cur_feat, cur_risk)
        self._frozen_evidence = cur_risk.get("evidence", [])
        self.forensic = {
            "captured_at": self.contain_ts,
            "process": {"image": self.sim.image, "pid": self.sim.pid, "state": "suspended"},
            "files_touched": self.sim.files_touched,
            "risk_score": cur_risk.get("score", 0),
            "peak_risk_score": max((h["risk"]["score"] for h in self.history), default=0),
            "evidence": self._frozen_evidence,
            "open_handles_snapshotted": self.sim.files_touched,
        }

    # ------------------------------------------------------------------ #

    def _signals(self, feat: dict, risk: dict) -> list[dict]:
        churn = feat["file_mod_rate"] + feat["file_rename_rate"]
        base = BASELINE["file_mod_rate"] + BASELINE["file_rename_rate"]
        sigma = round((churn - base) / 1.4)
        window_events = []
        lo = max(0, self.tick - 5)
        for h in self.history[lo:]:
            window_events += h["events_by_endpoint"].get(_ENDPOINT["id"], [])
        recovery = any(
            (e["type"] == "privilege" and e["action"] in ("shadow_copy_delete",))
            or (e["type"] == "process" and "shadow_copy_deletion" in e.get("suspicious_indicators", []))
            for e in window_events
        )
        return [
            {"key": "file_churn", "label": "File churn",
             "status": "critical" if sigma >= 8 else "warning" if sigma >= 3 else "ok",
             "value": f"+{sigma}σ" if sigma > 0 else "normal",
             "detail": f"{churn:.1f} file ops/tick vs {base:.1f} baseline"},
            {"key": "entropy", "label": "Entropy shift",
             "status": "critical" if feat["entropy_flip_rate"] > 0 else "ok",
             "value": "HIGH" if feat["entropy_flip_rate"] > 0 else "none",
             "detail": f"{feat['entropy_flip_rate']:.1f} plaintext→ciphertext flips/tick"},
            {"key": "recovery", "label": "Recovery inhibition",
             "status": "critical" if recovery else "ok",
             "value": "DETECTED" if recovery else "none",
             "detail": "vssadmin / bcdedit shadow-copy deletion" if recovery else "no recovery tampering"},
            {"key": "process", "label": "Process behavior",
             "status": "critical" if feat["suspicious_process_rate"] > 0 else "ok",
             "value": "SUSPICIOUS" if feat["suspicious_process_rate"] > 0 else "normal",
             "detail": f"{feat['suspicious_process_rate']:.1f} flagged process spawns/tick"},
            {"key": "network", "label": "Network behavior",
             "status": "critical" if feat["malicious_conn_rate"] > 0 else "ok",
             "value": "ANOMALOUS" if feat["malicious_conn_rate"] > 0 else "normal",
             "detail": f"{feat['malicious_conn_rate']:.1f} known-bad connections/tick"},
        ]

    def _timeline(self) -> list[dict]:
        out: list[dict] = []
        seen: set[str] = set()

        def add(key: str, ts: str, label: str, kind: str = "signal"):
            if key not in seen:
                seen.add(key)
                out.append({"sim_ts": ts, "label": label, "kind": kind})

        for h in self.history:
            evs = h["events_by_endpoint"].get(_ENDPOINT["id"], [])
            feat, ts = h.get("feat", {}), h["ts"]
            for e in evs:
                if e["type"] == "process" and {"encoded_command", "spawned_from_office_macro"} & set(e.get("suspicious_indicators", [])):
                    add("initial", ts, "Initial suspicious behavior")
                if e["type"] == "process" and "shadow_copy_deletion" in e.get("suspicious_indicators", []):
                    add("recovery", ts, "Recovery inhibition (vssadmin)")
                if e["type"] == "privilege" and e["action"] == "token_elevation":
                    add("priv", ts, "Privilege escalation to SYSTEM")
                if e["type"] == "network" and e.get("reputation") == "malicious":
                    add("c2", ts, "C2 beacon to known-bad host")
                if e["type"] == "file" and e.get("op") == "rename":
                    add("encrypt", ts, "Mass file rewrite begins")
            if feat.get("file_mod_rate", 0) + feat.get("file_rename_rate", 0) >= 10:
                add("churn", ts, "Abnormal file churn detected")
            if feat.get("entropy_flip_rate", 0) > 0:
                add("entropy", ts, "Plaintext→ciphertext entropy shift")
        if self.alert:
            add("warning", self.alert["timestamp"], "RANSOMEYE EARLY WARNING", "warning")
        if self.contained:
            add("contained", self.contain_ts, "CONTAINMENT executed", "contained")
        out.sort(key=lambda e: e["sim_ts"])
        return out

    def _detection(self) -> dict | None:
        if not self.alert:
            return None
        peak = max((h["risk"]["score"] for h in self.history), default=self.alert["risk_score"])
        lead = None
        cf = self.counterfactual
        if cf and cf.get("sim_seconds_to_catastrophe") is not None:
            detect_sec = self.alert["fired_at_tick"] * self.sim_tick_seconds
            lead = max(0, cf["sim_seconds_to_catastrophe"] - detect_sec)
        return {
            "detected": True,
            "tick": self.alert["fired_at_tick"],
            "sim_ts": self.alert["timestamp"],
            "confidence": peak,
            "lead_seconds": lead,
            "primary_signal": self.alert.get("primary_signal"),
        }

    def _containment(self) -> dict | None:
        if not self.contained:
            return None
        protected = self.corpus.remaining
        return {
            "contained": True,
            "tick": self.contain_tick,
            "sim_ts": self.contain_ts,
            "files_touched_at_containment": self.sim.files_touched,
            "files_protected": protected,
            "endpoint_status": "ISOLATED",
            "actions": [
                {"label": "Process suspended", "detail": f"{self.sim.image} (pid {self.sim.pid})", "done": True},
                {"label": "Endpoint isolated", "detail": f"{_ENDPOINT['id']} removed from CORP-DOMAIN", "done": True},
                {"label": "File operations stopped", "detail": "encryptor loop halted", "done": True},
                {"label": "Forensic state saved", "detail": "process list + open handles snapshotted", "done": True},
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        cur = self.history[-1] if self.history else None
        feat = cur["feat"] if cur else {k: 0.0 for k in BASELINE}
        risk = cur["risk"] if cur else {"score": 0, "level": "low", "factors": {}, "weighted_contribution_pct": {}, "evidence": []}
        return {
            "status": self.status,
            "profile": self.profile,
            "seed": self.seed,
            "sim_tick_seconds": self.sim_tick_seconds,
            "tick": self.tick,
            "sim_clock": self.sim.ts(max(self.tick, 0)),
            "endpoint": _ENDPOINT,
            "attacker": {"image": self.sim.image, "pid": self.sim.pid, "state": self.sim.state,
                         "profile": self.profile},
            "corpus": {
                "total": self.corpus.total, "encrypted": self.corpus.encrypted,
                "remaining": self.corpus.remaining, "pct_encrypted": self.corpus.pct_encrypted,
            },
            "files_touched": self.sim.files_touched,
            "rates": {
                "file_mod_rate": feat.get("file_mod_rate", 0.0),
                "file_rename_rate": feat.get("file_rename_rate", 0.0),
                "entropy_flip_rate": feat.get("entropy_flip_rate", 0.0),
                "malicious_conn_rate": feat.get("malicious_conn_rate", 0.0),
                "files_touched_window": feat.get("files_touched", 0),
            },
            "risk": {
                "score": risk["score"], "level": risk["level"],
                "factors": risk.get("factors", {}),
                "weighted_contribution_pct": risk.get("weighted_contribution_pct", {}),
                "ml_anomaly_score": risk.get("ml_anomaly_score"),
            },
            "signals": self._frozen_signals if self._frozen_signals is not None else self._signals(feat, risk),
            "evidence": self._frozen_evidence if self._frozen_evidence is not None else risk.get("evidence", []),
            "detection": self._detection(),
            "containment": self._containment(),
            "forensic": self.forensic,
            "timeline": self._timeline(),
            "counterfactual": self.counterfactual,
            "catastrophe_pct": _CATASTROPHE_PCT,
        }
