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


def _top_factors(ctx: dict, n: int = 3) -> str:
    ranked = sorted(ctx["factors"].items(), key=lambda kv: -kv[1])[:n]
    return ", ".join(f"{k.replace('_', ' ')} ({round(v * 100)}%)" for k, v in ranked if v > 0) or "no elevated factors"


def _template_answer(question: str, ctx: dict) -> str:
    """Structured analyst answer, composed from the real risk-engine output
    and telemetry evidence for this endpoint — deterministic, no LLM."""
    q = question.lower()
    ep, score, level = ctx["endpoint_id"], ctx["risk_score"], ctx["risk_level"]
    evidence = ctx.get("evidence") or []

    if any(k in q for k in ("do", "should", "action", "contain", "respond", "recommend")):
        lines = [f"**Recommended action for {ep}**", ""]
        lines.append(ctx.get("recommended_action") or "Continue monitoring — no action required at this risk level.")
        if score >= 60:
            lines += ["", "Stage endpoint isolation and process suspension for approval; both preserve forensic state."]
        return "\n".join(lines)

    if any(k in q for k in ("next", "happen", "forecast", "spread", "blast", "impact")):
        return (
            f"**Projected impact for {ep}**\n\n"
            f"At the current risk trend, 15-minute projection is {ctx.get('forecast_15m_risk', '—')}/100 "
            f"with roughly {ctx.get('forecast_15m_files', '—')} files touched on this endpoint. "
            "This is a deterministic projection of this host's own file trajectory — lateral spread is not modelled."
        )

    if any(k in q for k in ("observe", "behaviour", "behavior", "evidence", "what happened", "signal")):
        if not evidence:
            return f"**{ep}** — no ransomware tradecraft observed yet. Behavioural rates are within baseline."
        return f"**Observed on {ep}**\n\n" + "\n".join(f"- {e}" for e in evidence[:6])

    # default: "why flagged / status"
    if ctx.get("alert_fired") or score >= 60:
        verdict = "ransomware-like behaviour"
    elif score >= 30:
        verdict = "elevated but sub-threshold activity"
    else:
        verdict = "no ransomware tradecraft"
    lines = [
        f"**{ep} — {verdict}**",
        "",
        f"Current risk score {score}/100 ({level}), driven by {_top_factors(ctx)}."
        + (" Score shown is the latest tick; it decays as the burst tapers, but the evidence below is cumulative."
           if ctx.get("alert_fired") and score < 60 else ""),
    ]
    if evidence:
        lines += ["", "Key evidence:"] + [f"- {e}" for e in evidence[:4]]
    if ctx.get("alert_fired"):
        lines += ["", f"An early-warning alert has fired for this endpoint. {ctx.get('recommended_action', '')}".strip()]
    return "\n".join(lines)


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
            "status": "ok", "generated": "analysis", "provider": "ransomeye-analysis",
            "answer": _template_answer(payload.question, ctx),
            "note": "Composed directly from this endpoint's live risk-engine output and telemetry evidence.",
        }

    return {"status": "ok", "provider": used_provider, "model": used_model, "answer": answer}
