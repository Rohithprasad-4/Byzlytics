"""Combine the ML anomaly score with rule-based bonuses (Section 7.4).

    +15  dangerous destination port
    +20  extreme deviation in packet size (> 7x historical average)
    +18  extreme request volume (> 250 requests/hour)
    +12  scanning behaviour (> 15 unique destinations)
    +8   outside business hours
    +7   night activity (00:00-06:00)

Final score is re-clipped to [0, 100] after bonuses are applied.
"""

from __future__ import annotations

from typing import Any

from ml.predict import ModelNotTrainedError, risk_category, score_feature_row


def _rule_bonuses(features: dict[str, Any]) -> list[dict[str, Any]]:
    adjustments: list[dict[str, Any]] = []

    if features.get("is_dangerous_port"):
        adjustments.append({"rule": "dangerous_port", "delta": 15})

    deviation = float(features.get("deviation_score") or 0)
    if deviation > 7:
        adjustments.append({"rule": "extreme_deviation", "delta": 20})

    if float(features.get("requests_last_60min") or 0) > 250:
        adjustments.append({"rule": "extreme_request_volume", "delta": 18})

    if float(features.get("unique_destinations_60min") or 0) > 15:
        adjustments.append({"rule": "scanning_behaviour", "delta": 12})

    if not features.get("is_business_hours"):
        adjustments.append({"rule": "outside_business_hours", "delta": 8})

    if features.get("is_night"):
        adjustments.append({"rule": "night_activity", "delta": 7})

    return adjustments


def score_event(features: dict[str, Any]) -> dict[str, Any]:
    """Compute the final risk assessment for one feature row.

    Falls back to a rule-only score (base 20) if the ML model has not
    been trained yet, so the system remains usable before Phase 6 setup.
    """
    try:
        ml_result = score_feature_row(features)
        base_score = ml_result["base_risk_score"]
        anomaly_score = ml_result["raw_anomaly_score"]
        ml_score = base_score
        method = "isolation_forest"
    except ModelNotTrainedError:
        base_score = 20.0
        anomaly_score = None
        ml_score = None
        method = "rule_only_fallback"

    adjustments = _rule_bonuses(features)
    bonus_total = sum(a["delta"] for a in adjustments)
    final_score = min(100.0, base_score + bonus_total)

    return {
        "risk_score": round(final_score, 2),
        "risk_category": risk_category(final_score),
        "anomaly_score": anomaly_score,
        "ml_score": ml_score,
        "rule_adjustments": adjustments,
        "scoring_method": method,
    }
