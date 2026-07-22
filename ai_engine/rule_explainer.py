"""Section 8.3 — Rule-based fallback explanation engine.

Produces the same three-part output as the GPT engine (observation,
context, recommendation) using a template system, with no network
connectivity or API key required. Every protocol x risk-category
combination has a dedicated observation template; additional context
templates cover DNS flooding, port scanning, ICMP sweeping, dangerous
port access, and nighttime activity.
"""

from __future__ import annotations

from typing import Any

_OBSERVATION_TEMPLATES = {
    ("DNS", "Low"): "Device {ip} made {req60:.0f} DNS lookups in the last hour, within its normal range.",
    ("DNS", "Medium"): "Device {ip} made {req60:.0f} DNS requests in the last hour, above its usual pattern.",
    ("DNS", "High"): (
        "Device {ip} sent {req60:.0f} DNS requests in the last 60 minutes, "
        "which is {ratio:.1f}x above its historical baseline."
    ),
    ("TCP", "Low"): "Device {ip} opened a routine TCP connection to {dst} on port {dport}.",
    ("TCP", "Medium"): "Device {ip} opened {req60:.0f} TCP connections in the last hour, more than usual.",
    ("TCP", "High"): (
        "Device {ip} attempted {uniq60:.0f} distinct TCP connections to different destinations "
        "in the last hour, consistent with scanning behaviour."
    ),
    ("ICMP", "Low"): "Device {ip} sent a small number of ICMP (ping) packets, typical network diagnostics.",
    ("ICMP", "Medium"): "Device {ip} sent {req60:.0f} ICMP packets in the last hour, more than typical diagnostics.",
    ("ICMP", "High"): (
        "Device {ip} sent ICMP packets to {uniq60:.0f} different addresses in the last hour, "
        "consistent with a network sweep."
    ),
}

_CONTEXT_TEMPLATES = {
    "dangerous_port": (
        "The destination port {dport} is commonly associated with sensitive services "
        "(databases, remote desktop, or file sharing) that attackers frequently target."
    ),
    "extreme_deviation": (
        "The size of this traffic differs sharply from this device's historical average, "
        "which can indicate a different application, protocol, or malicious tooling running on it."
    ),
    "extreme_request_volume": (
        "This request rate is well above normal usage and is commonly associated with malware "
        "command-and-control (C2) beaconing or automated scripts."
    ),
    "scanning_behaviour": (
        "Contacting many distinct destinations in a short window is a classic signature of "
        "network reconnaissance or port scanning."
    ),
    "outside_business_hours": (
        "This activity occurred outside typical working hours, which increases the chance "
        "it was not initiated by a person."
    ),
    "night_activity": (
        "This activity occurred overnight (00:00-06:00), a common window for automated malicious "
        "traffic that tries to avoid detection."
    ),
    "baseline": "No unusual behavioural patterns were detected beyond normal traffic variation.",
}

_RECOMMENDATION_BY_CATEGORY = {
    "Low": "No action required. Activity is within expected parameters.",
    "Medium": "Monitor this device closely. Consider blocking if the activity persists or escalates.",
    "High": "Block this device immediately and investigate it for signs of compromise.",
}


def _observation(features: dict[str, Any], risk_category: str) -> str:
    protocol = features.get("protocol", "TCP")
    template = _OBSERVATION_TEMPLATES.get(
        (protocol, risk_category),
        "Device {ip} generated {protocol} traffic to {dst}.",
    )
    historical_avg = float(features.get("historical_avg_requests_per_hour") or 1) or 1
    ratio = float(features.get("requests_last_60min") or 0) / historical_avg

    return template.format(
        ip=features.get("source_ip", "unknown"),
        dst=features.get("destination_ip", "unknown"),
        dport=features.get("destination_port", "N/A"),
        req60=float(features.get("requests_last_60min") or 0),
        uniq60=float(features.get("unique_destinations_60min") or 0),
        ratio=ratio,
        protocol=protocol,
    )


def _context(rule_adjustments: list[dict[str, Any]], features: dict[str, Any]) -> str:
    if not rule_adjustments:
        return _CONTEXT_TEMPLATES["baseline"]

    parts = []
    for adjustment in rule_adjustments:
        template = _CONTEXT_TEMPLATES.get(adjustment["rule"])
        if template:
            parts.append(template.format(dport=features.get("destination_port", "N/A")))
    if features.get("is_night"):
        night_ctx = _CONTEXT_TEMPLATES["night_activity"]
        if night_ctx not in parts:
            parts.append(night_ctx)
    return " ".join(parts) if parts else _CONTEXT_TEMPLATES["baseline"]


def generate_explanation(
    features: dict[str, Any],
    risk_score: float,
    risk_category_value: str,
    rule_adjustments: list[dict[str, Any]],
) -> dict[str, str]:
    """Return {observation, context, recommendation} using template rules."""
    return {
        "observation": _observation(features, risk_category_value),
        "context": _context(rule_adjustments, features),
        "recommendation": _RECOMMENDATION_BY_CATEGORY.get(
            risk_category_value, _RECOMMENDATION_BY_CATEGORY["Medium"]
        ),
        "method": "rule_based_fallback",
    }
