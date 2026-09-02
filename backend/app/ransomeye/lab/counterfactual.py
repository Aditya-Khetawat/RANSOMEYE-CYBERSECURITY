"""Counterfactual replay — the same seeded attack profile run to completion
with no containment. This is where the "what would have happened" numbers
come from: they are measured off an actual replay, not asserted.
"""

from __future__ import annotations

from typing import Any

from ..features import extract_features
from ..risk_engine import score_risk
from .attacker import Profile, SafeAttackSimulator
from .corpus import FileCorpus

_MAX_TICKS = 200
_ENDPOINT_ID = "FINANCE-WS-042"
_CATASTROPHE_PCT = 0.9


def run_counterfactual(profile: Profile, seed: int, corpus_size: int,
                       sim_tick_seconds: int = 4) -> dict[str, Any]:
    corpus = FileCorpus(user="d.chen", total=corpus_size)
    sim = SafeAttackSimulator(profile, corpus, seed=seed, sim_tick_seconds=sim_tick_seconds)
    history: list[dict] = []

    catastrophe_tick: int | None = None
    peak_score = 0

    for t in range(_MAX_TICKS):
        events = sim.step(t)
        history.append({"events_by_endpoint": {_ENDPOINT_ID: events}, "tick": t})
        feat = extract_features(history, _ENDPOINT_ID, t)
        peak_score = max(peak_score, score_risk(feat)["score"])
        if catastrophe_tick is None and corpus.pct_encrypted >= _CATASTROPHE_PCT:
            catastrophe_tick = t
        if sim.state in ("done", "terminated"):
            break

    full_tick = t
    return {
        "profile": profile,
        "total_files": corpus.total,
        "files_encrypted": corpus.encrypted,
        "pct_encrypted": corpus.pct_encrypted,
        "ticks_to_full": full_tick,
        "sim_seconds_to_full": full_tick * sim_tick_seconds,
        "catastrophe_tick": catastrophe_tick,
        "sim_seconds_to_catastrophe": catastrophe_tick * sim_tick_seconds if catastrophe_tick is not None else None,
        "peak_risk": peak_score,
        "endpoint_status": "COMPROMISED" if corpus.pct_encrypted > 0.5 else "AFFECTED" if corpus.encrypted else "CLEAN",
    }
