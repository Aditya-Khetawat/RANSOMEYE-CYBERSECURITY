"""RansomEye Analyst Copilot — explains a flagged endpoint in plain English.

Reuses the alert correlation engine's assistant.py (app/assistant.py)
wholesale for the actual LLM plumbing
(_configured_providers/_call_chat_api: Cerebras-then-Groq, same .env, same
timeout/User-Agent handling) rather than duplicating an HTTP client — this
module only supplies ransomware-specific context building, prompting, and
the template fallback. The LLM is explicitly never the detector: it only
narrates a decision risk_engine.py already made from real telemetry.
"""

from __future__ import annotations

import urllib.error
from typing import Any

from pydantic import BaseModel, Field

from . import assistant_bridge as bridge

MAX_CONVERSATION_TURNS = 8

SYSTEM_PROMPT = (
    "You are RansomEye's SOC analyst copilot. Use only the supplied endpoint "
    "telemetry summary. Never invent processes, files, IPs, or timestamps not "
    "listed below. Be concise and technical. When asked, explain: why the "
    "endpoint was flagged, what behaviors were observed, what may happen next "
    "if unaddressed, and what the analyst should do right now."
)


class ConversationTurn(BaseModel):
    role: str
    content: str


class CopilotRequest(BaseModel):
    endpoint_id: str
    question: str
    conversation: list[ConversationTurn] = Field(default_factory=list)


def build_context(endpoint: dict, risk: dict, feat: dict, forecast: dict, alert: dict | None) -> dict:
    return {
        "endpoint_id": endpoint["id"],
        "hostname": endpoint["hostname"],
        "user": endpoint["user"],
        "department": endpoint["department"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "factors": risk["factors"],
        "evidence": risk.get("evidence", []),
        "forecast_15m_risk": forecast["forecast"][-1]["risk"] if forecast.get("forecast") else None,
        "forecast_15m_files": forecast["forecast"][-1].get("estimated_files_encrypted") if forecast.get("forecast") else None,
        "alert_fired": bool(alert),
        "recommended_action": (alert or forecast).get("recommended_action") or forecast.get("recommendedImmediateAction"),
    }


def _format_context(ctx: dict) -> str:
    lines = [
        f"Endpoint: {ctx['endpoint_id']} ({ctx['hostname']}), user {ctx['user']}, dept {ctx['department']}",
        f"Risk score: {ctx['risk_score']}/100 ({ctx['risk_level']})",
        "Risk factors (0..1 each): " + ", ".join(f"{k}={v}" for k, v in ctx["factors"].items()),
        "Observed evidence:",
    ]
    lines += [f"  - {e}" for e in ctx["evidence"]] if ctx["evidence"] else ["  - none yet"]
    lines.append(f"15-minute forecast: risk {ctx['forecast_15m_risk']}, ~{ctx['forecast_15m_files']} files touched")
    lines.append(f"Alert fired: {ctx['alert_fired']}")
    lines.append(f"Recommended action: {ctx['recommended_action']}")
    return "\n".join(lines)


def _template_answer(question: str, ctx: dict) -> str:
    q = question.lower()
    if any(k in q for k in ("why", "flagged", "risk")):
        return (f"{ctx['endpoint_id']} is at {ctx['risk_score']}/100 risk ({ctx['risk_level']}), driven mainly by "
                + ", ".join(f"{k} ({v})" for k, v in sorted(ctx["factors"].items(), key=lambda kv: -kv[1])[:2])
                + ". " + (ctx["evidence"][0] if ctx["evidence"] else "No specific evidence recorded yet."))
    if any(k in q for k in ("observe", "behavior", "evidence", "what happened")):
        return "Observed: " + "; ".join(ctx["evidence"]) if ctx["evidence"] else "No anomalous behavior recorded yet."
    if any(k in q for k in ("next", "happen", "forecast", "spread")):
        return f"At current trend, projected risk in 15 minutes is {ctx['forecast_15m_risk']}/100 with ~{ctx['forecast_15m_files']} files touched."
    if any(k in q for k in ("do", "should", "action", "contain")):
        return ctx["recommended_action"] or "Continue monitoring; no action required yet."
    return _format_context(ctx)


def ask_copilot(payload: CopilotRequest, ctx: dict) -> dict[str, Any]:
    providers = bridge.configured_providers()
    answer = None
    used_provider = used_model = None
    last_error = None

    if providers:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": "Endpoint telemetry summary:\n" + _format_context(ctx)},
        ]
        for turn in payload.conversation[-MAX_CONVERSATION_TURNS:]:
            messages.append({"role": turn.role, "content": turn.content.strip()})
        messages.append({"role": "user", "content": payload.question.strip()})

        for provider, api_key, url, model in providers:
            try:
                answer = bridge.call_chat_api(api_key, url, model, messages)
                used_provider, used_model = provider, model
                break
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError, TimeoutError, ValueError) as exc:
                last_error = f"{provider}: {exc}"
    else:
        last_error = "no AI provider key configured"

    if not answer or not answer.strip():
        return {
            "status": "ok", "generated": "template", "provider": "template",
            "answer": "_AI provider unreachable — answering directly from real endpoint telemetry:_\n\n" + _template_answer(payload.question, ctx),
            "note": f"AI providers unreachable ({last_error}); answered from real detection data instead.",
        }

    return {"status": "ok", "provider": used_provider, "model": used_model, "answer": answer}
