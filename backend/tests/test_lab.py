"""Tests for the Attack Lab sandbox — the "PROVE IT" surface.

The claims under test:
  * the simulator never touches a real filesystem (it can't — no os import)
  * detection genuinely precedes mass encryption on the RANSOMWARE profile
  * containment actually stops the encryptor (counters freeze)
  * NORMAL / SUSPICIOUS never trip an alert
  * the before/after numbers reconcile against the counterfactual
"""

from __future__ import annotations

import pytest

from app.ransomeye.lab import runner
from app.ransomeye.lab.counterfactual import run_counterfactual
from app.ransomeye.lab.sandbox import LabSession


@pytest.fixture(autouse=True)
def _reset_runner():
    runner.reset()
    yield
    runner.reset()


def _run_until(session: LabSession, pred, cap=120):
    for _ in range(cap):
        session.advance()
        if pred(session):
            return
    raise AssertionError("predicate never satisfied")


class TestRansomwareProfile:
    def test_detection_precedes_mass_encryption(self):
        s = LabSession("RANSOMWARE", seed=7)
        _run_until(s, lambda x: x.alert is not None)
        enc_at_detection = s.corpus.encrypted
        # warning fires while (almost) nothing is encrypted yet
        assert enc_at_detection <= s.corpus.total * 0.02
        assert s.alert["fired_at_tick"] <= s.counterfactual["catastrophe_tick"]

    def test_detection_lead_time_is_positive(self):
        s = LabSession("RANSOMWARE", seed=7)
        _run_until(s, lambda x: x.alert is not None)
        d = s.to_dict()["detection"]
        assert d["lead_seconds"] is not None and d["lead_seconds"] > 0

    def test_containment_freezes_the_counters(self):
        s = LabSession("RANSOMWARE", seed=7)
        _run_until(s, lambda x: x.corpus.encrypted > 500)
        s.contain()
        touched = s.corpus.encrypted
        for _ in range(20):
            s.advance()
        assert s.corpus.encrypted == touched
        assert s.sim.state == "terminated"

    def test_before_after_numbers_reconcile(self):
        s = LabSession("RANSOMWARE", seed=7, corpus_size=50_000)
        _run_until(s, lambda x: x.corpus.encrypted > 1000)
        s.contain()
        c = s.to_dict()["containment"]
        assert c["files_touched_at_containment"] + c["files_protected"] == 50_000
        assert c["files_protected"] > c["files_touched_at_containment"]
        # the counterfactual would have taken essentially everything
        assert s.counterfactual["pct_encrypted"] >= 0.9


class TestBenignProfiles:
    @pytest.mark.parametrize("profile", ["NORMAL", "SUSPICIOUS"])
    def test_never_alerts(self, profile):
        s = LabSession(profile, seed=7)
        for _ in range(40):
            s.advance()
        assert s.alert is None
        assert s.to_dict()["detection"] is None

    def test_suspicious_has_high_churn_but_no_tradecraft(self):
        s = LabSession("SUSPICIOUS", seed=7)
        for _ in range(10):
            s.advance()
        sigs = {x["key"]: x for x in s.to_dict()["signals"]}
        assert sigs["recovery"]["status"] == "ok"
        assert sigs["entropy"]["status"] == "ok"
        assert sigs["network"]["status"] == "ok"


class TestCounterfactual:
    def test_ransomware_counterfactual_encrypts_everything(self):
        cf = run_counterfactual("RANSOMWARE", 7, 50_000)
        assert cf["pct_encrypted"] >= 0.95
        assert cf["sim_seconds_to_catastrophe"] is not None
        assert cf["endpoint_status"] == "COMPROMISED"

    def test_normal_counterfactual_is_clean(self):
        cf = run_counterfactual("NORMAL", 7, 50_000)
        assert cf["files_encrypted"] == 0
        assert cf["endpoint_status"] == "CLEAN"


class TestApi:
    def test_full_lab_flow(self, client):
        r = client.post("/ransomeye/lab/start?profile=RANSOMWARE&seed=7")
        assert r.status_code == 200
        assert r.json()["status"] == "running"
        assert r.json()["counterfactual"]["pct_encrypted"] >= 0.9

        state = client.get("/ransomeye/lab")
        assert state.status_code == 200
        assert state.json()["endpoint"]["id"] == "FINANCE-WS-042"

        contain = client.post("/ransomeye/lab/contain")
        assert contain.status_code == 200
        body = contain.json()
        assert body["status"] == "contained"
        assert body["containment"]["endpoint_status"] == "ISOLATED"

        client.post("/ransomeye/lab/reset")
        assert client.get("/ransomeye/lab").json()["status"] == "idle"

    def test_contain_without_session_is_conflict(self, client):
        client.post("/ransomeye/lab/reset")
        assert client.post("/ransomeye/lab/contain").status_code == 409

    def test_bad_profile_rejected(self, client):
        assert client.post("/ransomeye/lab/start?profile=BOGUS").status_code == 400
