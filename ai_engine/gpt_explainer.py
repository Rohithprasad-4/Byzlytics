"""Section 8.2 — GPT-3.5 explanation generation.

Converts numerical features into human-readable sentences before
prompting GPT, so the model reasons over 'this device sent 4.1x more
DNS requests than its baseline of 35/hour' rather than raw column
values. Temperature is fixed at 0.3 for conservative, repeatable
output. Raises on any failure so the caller (ai_engine.py) can fall
back to the rule-based engine.
"""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are a cybersecurity analyst explaining network security events to \
non-technical home and small-office users. Hard rules:
- Never use jargon without immediately defining it in plain English.
- Always reference the specific IP address, protocol, and numerical values from the event.
- Maintain a calm, informative tone. Never be alarmist.
- Respond ONLY with a valid JSON object containing exactly three keys: \
observation, context, recommendation.
- Keep the total explanation under 120 words."""


def _humanize_features(features: dict[str, Any], risk_score: float, risk_category: str) -> str:
    historical_avg = float(features.get("historical_avg_requests_per_hour") or 0)
    requests_60 = float(features.get("requests_last_60min") or 0)
    ratio = requests_60 / historical_avg if historical_avg > 0 else 0

    lines = [
        f"Source IP: {features.get('source_ip')}",
        f"Destination IP: {features.get('destination_ip')}",
        f"Protocol: {features.get('protocol')}",
        f"Destination port: {features.get('destination_port')}",
        f"Requests in the last hour: {requests_60:.0f}, historical average {historical_avg:.0f}/hr "
        f"({ratio:.2f}x above historical average)" if historical_avg else
        f"Requests in the last hour: {requests_60:.0f}",
        f"Distinct destinations contacted in the last hour: {features.get('unique_destinations_60min', 0):.0f}",
        f"Occurred during {'nighttime (00:00-06:00)' if features.get('is_night') else 'daytime'} hours,"
        f" {'inside' if features.get('is_business_hours') else 'outside'} normal business hours",
        f"Destination port considered high-risk: {'yes' if features.get('is_dangerous_port') else 'no'}",
        f"Computed risk score: {risk_score:.1f}/100 ({risk_category})",
    ]
    return "\n".join(lines)


def generate_explanation(
    features: dict[str, Any],
    risk_score: float,
    risk_category: str,
    api_key: str | None,
    *,
    model: str = "gpt-3.5-turbo",
    temperature: float = 0.3,
) -> dict[str, str]:
    """Call the OpenAI API. Raises RuntimeError/ImportError/etc. on any failure —
    callers must catch and fall back to ai_engine.rule_explainer."""
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")

    from openai import OpenAI

    client = OpenAI(api_key=api_key)
    user_prompt = (
        "Explain this network security event to a non-technical user:\n\n"
        + _humanize_features(features, risk_score, risk_category)
    )

    response = client.chat.completions.create(
        model=model,
        temperature=temperature,
        max_tokens=300,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )

    content = response.choices[0].message.content
    parsed = json.loads(content)

    for key in ("observation", "context", "recommendation"):
        if key not in parsed:
            raise ValueError(f"GPT response missing required key: {key}")

    parsed["method"] = "gpt-3.5"
    return parsed
