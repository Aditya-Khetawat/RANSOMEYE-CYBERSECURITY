"""RansomEye Attack Lab — the "PROVE IT" sandbox.

A controlled, safe cyber range. A benign simulator drives a real attack
*profile* against an in-memory synthetic endpoint (a file corpus that only
ever exists as counters and sample paths — nothing on disk is ever touched).
Every operation it performs emits real telemetry into RansomEye's actual
detection pipeline (features -> risk_engine -> alerts), tick by tick, live.

When an analyst hits CONTAIN, the simulator's process is genuinely suspended
(the loop stops mutating the corpus), the endpoint is marked isolated, and a
forensic snapshot is taken. The counters freeze where they stopped.

A counterfactual replay of the same seeded profile with no intervention
gives the "what would have happened" numbers — measured, not asserted.

    sandbox.py         LabSession: corpus + simulator + live detector output
    attacker.py        SafeAttackSimulator: the benign profile-driven driver
    corpus.py          synthetic file corpus (counters + a sample path pool)
    counterfactual.py  same attack, run to completion, no containment
    runner.py          background-thread lifecycle for one live session
    api.py             /ransomeye/lab/* routes
"""

from .runner import lab_router

__all__ = ["lab_router"]
