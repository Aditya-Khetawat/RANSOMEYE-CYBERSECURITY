# RansomEye — 3-minute judge walkthrough

Run **Judge Mode** (the orange pill, bottom-left of any page) to have the app
drive this itself. This script is the manual version and the talk track.

> **Opening line:** *"Ransomware isn't dangerous when the first file encrypts —
> it's dangerous when defenders realise too late. RansomEye buys that time
> back."*

| # | Page | What to show | Say |
|---|------|--------------|-----|
| 1 | **Command Center** (`/`) | Load the `RANSOMWARE` scenario, scrub to ~tick 7. Point at the **Kill Chain** strip. | "One real seeded scenario replaying its telemetry. Initial access and recovery inhibition have fired — encryption hasn't. This is the window." |
| 2 | **Detection** (`/detection`) | Scrub to ~tick 15. The **five signal bars** + the **correlated verdict**. | "Five independent behavioural signals, each contributing to a weighted score you can audit. The verdict is corroboration, not one number." |
| 3 | **Detection** — switch to `SUSPICIOUS` | Same page, verdict stays *not ransomware*. | "The same detector on a noisy backup job: heavy churn, no tradecraft. Not ransomware. Suppressing the alert you *shouldn't* raise is the hard part." |
| 4 | **Evidence** (`/evidence`) | Back to `RANSOMWARE`, ~tick 16. The **attack chain** + **MITRE-mapped contributions** + the greyed-out *absent* signals. | "Every verdict backed by observable evidence, mapped to ATT&CK — and it shows the absences, which is what keeps the negative verdict honest." |
| 5 | **Blast Radius** (`/blast-radius`) | The +5 / +10 / +15 min projection and the containment comparison. | "A deterministic projection of this host's own file trajectory. Labelled an estimate — we don't invent lateral-spread numbers we can't measure." |
| 6 | **Containment** (`/containment`) | Approve **Isolate endpoint**. Watch the posture flip + the fleet-map link sever. | "One click: process suspended, endpoint isolated, forensics snapshotted. Destructive actions are approval-gated." |
| 7 | **Attack Lab** (`/lab`) | Click **Run Attack** (`RANSOMWARE`). Let it run ~10s. | "Now don't take the dashboard's word for it. This is a live controlled attack on a synthetic 50k-file endpoint, through the *same* pipeline — nothing touches a real disk." |
| 8 | **Attack Lab** — **Contain** | The before/after: files touched vs files protected, the advantage window. | "Detected during staging. Same attack, same seed — with RansomEye, tens of thousands of files never encrypted." |
| 9 | **Trust & Evaluation** (`/evaluation`) | Precision / recall / F1, and the smash-and-grab row. | "Measured across 24 seeds, recomputed server-side. Including the honest part: the fastest attacks give almost no head start. Detection holds; the warning window doesn't." |

**Close:** *"SEE the attack forming, PROVE it under a live attack, UNDERSTAND the
evidence, PREDICT the blast radius, STOP it. That's RansomEye."*

## Fallback if the backend is cold

`/evaluation` is warmed on startup but the first hit can still lag on a
free-tier host — open it once before judging. The Attack Lab and scenario
replay are fully local to the backend and need no external services.
