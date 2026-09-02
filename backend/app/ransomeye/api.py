"""RansomEye ransomware-detection API — FastAPI router, included by main.py
alongside the alert correlation engine's existing routes (kept fully
separate/untouched). Mirrors main.py's own
in-memory `_state` + `run_pipeline` pattern: one module-level dict holding
the currently-loaded scenario run, recomputed wholesale on each /demo/*
call, read by every GET below.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from . import containment as containment_mod
from . import copilot as copilot_mod
from . import demo as demo_mod
from . import evaluation as evaluation_mod
from .forecast import compute_forecast

router = APIRouter(prefix="/ransomeye", tags=["ransomeye"])

_state: dict[str, Any] = {"run": None, "containment_by_endpoint": {}, "evaluation": None}


def _require_run() -> dict:
    if _state["run"] is None:
        raise HTTPException(status_code=404, detail="No scenario loaded yet — call POST /ransomeye/demo/{scenario} first.")
    return _state["run"]


def _find_endpoint(run: dict, endpoint_id: str) -> dict:
    ep = next((e for e in run["endpoints"] if e["id"] == endpoint_id), None)
    if not ep:
        raise HTTPException(status_code=404, detail=f"Endpoint {endpoint_id} not found in current run.")
    return ep


@router.post("/demo/{scenario}")
def load_demo_scenario(scenario: str, seed: int | None = None) -> dict:
    if scenario not in demo_mod.SCENARIOS:
        raise HTTPException(status_code=400, detail=f"scenario must be one of {demo_mod.SCENARIOS}")
    run = demo_mod.run_scenario(scenario, seed=seed)
    _state["run"] = run
    _state["containment_by_endpoint"] = {}
    return run


@router.get("/state")
def get_state() -> dict:
    return _require_run()


@router.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str, at_tick: int | None = None) -> dict:
    run = _require_run()
    ep = _find_endpoint(run, endpoint_id)
    state = demo_mod.latest_endpoint_state(run, endpoint_id, at_tick)
    if not state:
        raise HTTPException(status_code=404, detail=f"No telemetry yet for {endpoint_id} at tick {at_tick}.")
    return {
        "endpoint": ep,
        "feat": state["feat"],
        "risk": state["risk"],
        "risk_history": demo_mod.endpoint_risk_history(run, endpoint_id, at_tick),
        "alert": demo_mod.latest_alert(run, endpoint_id),
    }


@router.get("/endpoints/{endpoint_id}/forecast")
def get_endpoint_forecast(endpoint_id: str, at_tick: int | None = None) -> dict:
    run = _require_run()
    ep = _find_endpoint(run, endpoint_id)
    state = demo_mod.latest_endpoint_state(run, endpoint_id, at_tick)
    if not state:
        raise HTTPException(status_code=404, detail=f"No telemetry yet for {endpoint_id} at tick {at_tick}.")
    history = demo_mod.endpoint_risk_history(run, endpoint_id, at_tick)
    return compute_forecast(ep, history, state["feat"])


@router.get("/endpoints/{endpoint_id}/containment")
def get_containment_plan(endpoint_id: str) -> dict:
    run = _require_run()
    ep = _find_endpoint(run, endpoint_id)
    if endpoint_id not in _state["containment_by_endpoint"]:
        state = demo_mod.latest_endpoint_state(run, endpoint_id)
        if not state:
            raise HTTPException(status_code=404, detail=f"No telemetry yet for {endpoint_id}.")
        _state["containment_by_endpoint"][endpoint_id] = containment_mod.generate_containment_plan(
            ep, state["risk"], state["feat"]
        )
    return {"endpoint_id": endpoint_id, "actions": _state["containment_by_endpoint"][endpoint_id]}


@router.post("/endpoints/{endpoint_id}/containment/{action_id}/approve")
def approve_containment_action(endpoint_id: str, action_id: str) -> dict:
    _require_run()
    actions = _state["containment_by_endpoint"].get(endpoint_id)
    if not actions:
        raise HTTPException(status_code=404, detail=f"No containment plan generated yet for {endpoint_id} — call GET .../containment first.")
    action = containment_mod.approve_action(actions, action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found in {endpoint_id}'s containment plan.")
    return {"endpoint_id": endpoint_id, "action": action}


@router.get("/evaluation")
def get_evaluation() -> dict:
    """Can we trust it? Runs every scenario at every seed for real (see
    evaluation.py) and caches the result — this is a real measurement, not a
    per-request recomputation, same reasoning as the alert correlation
    engine's own /evaluation (app/main.py)."""
    if _state["evaluation"] is None:
        _state["evaluation"] = evaluation_mod.compute_evaluation()
    return _state["evaluation"]


@router.post("/copilot")
def ask_copilot(payload: copilot_mod.CopilotRequest) -> dict:
    run = _require_run()
    ep = _find_endpoint(run, payload.endpoint_id)
    state = demo_mod.latest_endpoint_state(run, payload.endpoint_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"No telemetry yet for {payload.endpoint_id}.")
    history = demo_mod.endpoint_risk_history(run, payload.endpoint_id)
    forecast = compute_forecast(ep, history, state["feat"])
    alert = demo_mod.latest_alert(run, payload.endpoint_id)
    ctx = copilot_mod.build_context(ep, state["risk"], state["feat"], forecast, alert)
    return copilot_mod.ask_copilot(payload, ctx)
