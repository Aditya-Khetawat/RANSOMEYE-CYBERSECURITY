"""RansomEye's ransomware-detection core — AI-powered real-time ransomware
early warning.

Built on top of the alert correlation engine's pipeline architecture and
reusing its explainable-scoring / LLM-with-template-fallback conventions
(see risk_score.py, forecast.py, playbook.py, summarizer.py, assistant.py
one level up), but with an entirely new detection core: this package owns
telemetry, feature extraction, behavioral anomaly detection, risk scoring,
forecasting and containment for host-level ransomware behavior — a
different problem from the alert correlation engine's text-alert
correlation.
"""
