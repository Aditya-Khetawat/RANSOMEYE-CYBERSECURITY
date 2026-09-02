"""Tests for the RansomEye ransomware-detection core — the new detection
engine, distinct from the backend's existing alert correlation engine.
Mirrors this repo's existing test style: real computation, no
mocking of the pipeline itself (only the LLM network calls, via the autouse
no_real_llm_calls_by_default fixture in conftest.py)."""

from __future__ import annotations

import pytest

from app.ransomeye import demo
from app.ransomeye.alerts import ALERT_THRESHOLD


@pytest.fixture(autouse=True)
def isolated_ransomeye_state():
    """app.ransomeye.api._state is a module-level singleton (mirrors
    main.py's own _state) — reset it around every test so scenario state
    from one test (or a leftover background initial-load) never leaks into
    the next, same isolation concern conftest.py's isolated_db handles for
    the database."""
    from app.ransomeye import api as ransomeye_api

    ransomeye_api._state["run"] = None
    ransomeye_api._state["containment_by_endpoint"] = {}
    ransomeye_api._state["evaluation"] = None
    yield
    ransomeye_api._state["run"] = None
    ransomeye_api._state["containment_by_endpoint"] = {}
    ransomeye_api._state["evaluation"] = None


class TestScenarioSeparation:
    """The core false-positive/true-positive claim: normal activity and a
    merely-anomalous-but-benign endpoint must never cross the alert
    threshold, while a real attack must."""

    def test_normal_activity_never_alerts(self):
        run = demo.run_scenario("NORMAL_ACTIVITY", seed=7)
        assert run["alerts"] == []
        assert run["summary"]["final_status"] == "NORMAL"

    def test_suspicious_activity_never_alerts(self):
        run = demo.run_scenario("SUSPICIOUS_ACTIVITY", seed=7)
        assert run["alerts"] == []
        assert run["summary"]["peak_risk_score"] < ALERT_THRESHOLD
        assert run["summary"]["final_status"] == "ANOMALY_OBSERVED_NO_ALERT"

    def test_ransomware_attack_fires_exactly_one_alert(self):
        run = demo.run_scenario("RANSOMWARE_ATTACK", seed=7)
        assert len(run["alerts"]) == 1
        alert = run["alerts"][0]
        assert alert["endpoint_id"] == run["target_endpoint_id"]
        assert alert["risk_score"] >= ALERT_THRESHOLD
        assert alert["severity"] in ("high", "critical")
        assert alert["contributing_behaviors"]  # non-empty, real evidence
        assert run["summary"]["final_status"] == "CONTAINED_ALERT_FIRED"

    def test_ransomware_attack_is_reproducible_under_a_seed(self):
        run_a = demo.run_scenario("RANSOMWARE_ATTACK", seed=42)
        run_b = demo.run_scenario("RANSOMWARE_ATTACK", seed=42)
        assert [a["risk_score"] for a in run_a["alerts"]] == [a["risk_score"] for a in run_b["alerts"]]

    def test_invalid_scenario_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            demo.run_scenario("NOT_A_REAL_SCENARIO")


class TestRiskHistoryAndForecast:
    def test_risk_history_is_monotonic_in_tick(self):
        run = demo.run_scenario("RANSOMWARE_ATTACK", seed=7)
        history = demo.endpoint_risk_history(run, run["target_endpoint_id"])
        assert [h["tick"] for h in history] == sorted(h["tick"] for h in history)

    def test_forecast_reflects_rising_trend_at_peak(self):
        from app.ransomeye.forecast import compute_forecast

        run = demo.run_scenario("RANSOMWARE_ATTACK", seed=7)
        target = run["target_endpoint_id"]
        ep = next(e for e in run["endpoints"] if e["id"] == target)
        alert = run["alerts"][0]
        # Forecast from right at the alert tick, while risk is still climbing.
        history = demo.endpoint_risk_history(run, target, upto_tick=alert["fired_at_tick"])
        feat = run["ticks"][alert["fired_at_tick"]]["endpoint_states"][target]["feat"]
        fc = compute_forecast(ep, history, feat)
        assert fc["forecast"][-1]["risk"] >= fc["currentRisk"]
        assert "isolate" in fc["recommendedImmediateAction"].lower() or "escalate" in fc["recommendedImmediateAction"].lower() or "prepare" in fc["recommendedImmediateAction"].lower()


class TestContainmentPlan:
    def test_destructive_actions_require_approval_and_start_pending(self):
        from app.ransomeye.containment import generate_containment_plan

        run = demo.run_scenario("RANSOMWARE_ATTACK", seed=7)
        target = run["target_endpoint_id"]
        ep = next(e for e in run["endpoints"] if e["id"] == target)
        state = demo.latest_endpoint_state(run, target, run["alerts"][0]["fired_at_tick"])
        plan = generate_containment_plan(ep, state["risk"], state["feat"])

        destructive = [a for a in plan if a["destructive"]]
        assert destructive, "expected at least one destructive containment action"
        assert all(a["requires_approval"] and a["status"] == "pending_approval" for a in destructive)

        non_destructive = [a for a in plan if not a["destructive"]]
        assert all(a["status"] == "executed" for a in non_destructive)

    def test_approve_action_flips_status(self):
        from app.ransomeye.containment import approve_action, generate_containment_plan

        run = demo.run_scenario("RANSOMWARE_ATTACK", seed=7)
        target = run["target_endpoint_id"]
        ep = next(e for e in run["endpoints"] if e["id"] == target)
        state = demo.latest_endpoint_state(run, target)
        plan = generate_containment_plan(ep, state["risk"], state["feat"])
        pending = next(a for a in plan if a["requires_approval"])

        approved = approve_action(plan, pending["id"])
        assert approved["status"] == "executed"


class TestApi:
    """End-to-end through the actual FastAPI routes (client fixture from
    conftest.py — isolated DB, no real LLM calls)."""

    def test_state_404_before_any_demo_load(self, client):
        resp = client.get("/ransomeye/state")
        assert resp.status_code == 404

    def test_full_demo_flow(self, client, monkeypatch):
        # copilot.py reuses assistant.py's LLM plumbing via assistant_bridge.py
        # ("from ..assistant import X as Y" binds a new name, so patching
        # assistant.py itself wouldn't reach it) — the autouse
        # no_real_llm_calls_by_default fixture only patches summarizer.py, so
        # guard the bridge's provider list here too, same as test_assistant.py
        # does for the /assistant endpoint.
        from app.ransomeye import assistant_bridge
        monkeypatch.setattr(assistant_bridge, "configured_providers", lambda: [])

        resp = client.post("/ransomeye/demo/RANSOMWARE_ATTACK?seed=7")
        assert resp.status_code == 200
        run = resp.json()
        assert run["scenario"] == "RANSOMWARE_ATTACK"
        target = run["target_endpoint_id"]

        state_resp = client.get("/ransomeye/state")
        assert state_resp.status_code == 200
        assert state_resp.json()["run_id"] == run["run_id"]

        detail = client.get(f"/ransomeye/endpoints/{target}")
        assert detail.status_code == 200
        assert detail.json()["risk"]["score"] >= 0

        forecast = client.get(f"/ransomeye/endpoints/{target}/forecast")
        assert forecast.status_code == 200
        assert "forecast" in forecast.json()

        plan = client.get(f"/ransomeye/endpoints/{target}/containment")
        assert plan.status_code == 200
        actions = plan.json()["actions"]
        assert actions

        pending = next(a for a in actions if a["requires_approval"])
        approve = client.post(f"/ransomeye/endpoints/{target}/containment/{pending['id']}/approve")
        assert approve.status_code == 200
        assert approve.json()["action"]["status"] == "executed"

        copilot = client.post("/ransomeye/copilot", json={
            "endpoint_id": target,
            "question": "why was this endpoint flagged?",
        })
        assert copilot.status_code == 200
        assert copilot.json()["answer"]

    def test_invalid_scenario_rejected_by_api(self, client):
        resp = client.post("/ransomeye/demo/NOT_A_SCENARIO")
        assert resp.status_code == 400

    def test_unknown_endpoint_404s(self, client):
        client.post("/ransomeye/demo/NORMAL_ACTIVITY?seed=7")
        resp = client.get("/ransomeye/endpoints/DOES-NOT-EXIST")
        assert resp.status_code == 404

    def test_evaluation_endpoint_shape(self, client):
        resp = client.get("/ransomeye/evaluation")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data["per_scenario"]) == {"NORMAL_ACTIVITY", "SUSPICIOUS_ACTIVITY", "RANSOMWARE_ATTACK"}
        assert data["precision"] is not None
        assert data["recall"] is not None

    def test_evaluation_is_cached_across_calls(self, client):
        first = client.get("/ransomeye/evaluation").json()
        second = client.get("/ransomeye/evaluation").json()
        assert first == second


class TestEvaluation:
    """Runs the real evaluation once (slow: exercises every scenario at
    every seed) and asserts on the actual measured outcome, not a fixed
    expectation — this is what "can we trust it?" has to mean: the number
    comes from executing demo.run_scenario for real, not from a constant."""

    @staticmethod
    @pytest.fixture(scope="class")
    def result():
        from app.ransomeye.evaluation import compute_evaluation
        return compute_evaluation()

    def test_zero_false_positives_across_negative_scenarios(self, result):
        # NORMAL_ACTIVITY and SUSPICIOUS_ACTIVITY must never fire — this is
        # the same false-positive-control claim the scenarios themselves
        # make, now checked across every seed instead of just seed=7.
        assert result["confusion_matrix"]["fp"] == 0
        assert result["false_positive_rate"] == 0.0

    def test_full_detection_of_both_kill_chain_variants(self, result):
        ransomware = result["per_scenario"]["RANSOMWARE_ATTACK"]
        assert ransomware["full_kill_chain"]["detection_rate_pct"] == 100.0
        assert ransomware["smash_and_grab"]["detection_rate_pct"] == 100.0

    def test_full_kill_chain_gives_more_advance_warning_than_smash_and_grab(self, result):
        # An honest, disclosed tradeoff, not a claim: the smash-and-grab
        # variant skips the early privilege-escalation/shadow-copy signals,
        # so the alert has fewer independent signals to fire on ahead of the
        # encryption itself, and warns later on average as a result.
        ransomware = result["per_scenario"]["RANSOMWARE_ATTACK"]
        full_lead = ransomware["full_kill_chain"]["mean_lead_seconds"]
        smash_lead = ransomware["smash_and_grab"]["mean_lead_seconds"]
        assert full_lead is not None and smash_lead is not None
        assert full_lead > smash_lead

    def test_precision_recall_f1_are_internally_consistent(self, result):
        cm = result["confusion_matrix"]
        tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
        assert (tp + fp) > 0 and (tp + fn) > 0, "expected a mix of positive/negative runs in the seed set"
        assert result["precision"] == round(tp / (tp + fp), 3)
        assert result["recall"] == round(tp / (tp + fn), 3)
