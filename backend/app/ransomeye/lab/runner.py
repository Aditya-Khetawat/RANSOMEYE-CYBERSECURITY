"""Live-session lifecycle + the /ransomeye/lab/* API.

One global session at a time (a demo surface, not multi-tenant). A daemon
thread advances it on a wall-clock timer; the frontend polls GET
/ransomeye/lab. If the thread dies for any reason the session just stops
advancing — the last state stays readable.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from .attacker import Profile
from .sandbox import LabSession

_TICK_INTERVAL_SEC = 0.9          # wall-clock between ticks
_MAX_TICKS = 160

_lock = threading.RLock()
_session: LabSession | None = None
_thread: threading.Thread | None = None
_generation = 0                  # bumped on every start(); an old loop whose
                                 # generation no longer matches exits itself


def _loop(generation: int) -> None:
    while True:
        time.sleep(_TICK_INTERVAL_SEC)
        with _lock:
            if generation != _generation:
                return
            s = _session
            if s is None:
                return
            if s.contained or s.sim.state in ("done", "terminated") or s.tick >= _MAX_TICKS:
                return
            s.advance()


def start(profile: Profile, seed: int = 7, corpus_size: int = 50_000) -> dict:
    global _session, _thread, _generation
    with _lock:
        _generation += 1                 # invalidate any running loop
        gen = _generation
        _session = LabSession(profile, seed=seed, corpus_size=corpus_size)
        _session.advance()               # tick 0 immediately
        _thread = threading.Thread(target=_loop, args=(gen,), name="ransomeye-lab", daemon=True)
        _thread.start()
        return _session.to_dict()


def contain() -> dict:
    with _lock:
        if _session is None:
            raise HTTPException(status_code=409, detail="No lab session running — start one first.")
        _session.contain()
        return _session.to_dict()


def get() -> dict:
    with _lock:
        if _session is None:
            return {"status": "idle"}
        return _session.to_dict()


def reset() -> dict:
    global _session, _generation
    with _lock:
        _generation += 1
        _session = None
        return {"status": "idle"}


lab_router = APIRouter(prefix="/ransomeye/lab", tags=["ransomeye-lab"])

_PROFILES = ("NORMAL", "SUSPICIOUS", "RANSOMWARE")


@lab_router.post("/start")
def lab_start(
    profile: str = Query("RANSOMWARE"),
    seed: int = Query(7),
    corpus_size: int = Query(50_000, ge=1_000, le=500_000),
) -> dict:
    profile = profile.upper()
    if profile not in _PROFILES:
        raise HTTPException(status_code=400, detail=f"profile must be one of {_PROFILES}")
    return start(profile, seed=seed, corpus_size=corpus_size)  # type: ignore[arg-type]


@lab_router.get("")
def lab_state() -> dict:
    return get()


@lab_router.post("/contain")
def lab_contain() -> dict:
    return contain()


@lab_router.post("/reset")
def lab_reset() -> dict:
    return reset()


@lab_router.get("/counterfactual")
def lab_counterfactual(
    profile: str = Query("RANSOMWARE"),
    seed: int = Query(7),
    corpus_size: int = Query(50_000, ge=1_000, le=500_000),
) -> dict[str, Any]:
    from .counterfactual import run_counterfactual

    profile = profile.upper()
    if profile not in _PROFILES:
        raise HTTPException(status_code=400, detail=f"profile must be one of {_PROFILES}")
    return run_counterfactual(profile, seed, corpus_size)  # type: ignore[arg-type]
