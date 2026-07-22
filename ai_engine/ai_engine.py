"""Phase 7 orchestrator — ties the pipeline, ML scorer, and explainers together.

For each event: build/enrich features -> score with Isolation Forest +
rule bonuses -> generate an explanation (GPT-3.5, falling back to the
rule-based engine) -> persist the complete assessment to
risk_assessment and mark the event processed=TRUE.
"""

from __future__ import annotations

import logging
from typing import Any

from ai_engine import gpt_explainer, rule_explainer
from ai_engine.risk_scorer import score_event
from backend import models
from ml.features import FEATURE_COLUMNS
from pipeline.pipeline import run_pipeline

logger = logging.getLogger(__name__)


def _feature_row_to_dict(row) -> dict[str, Any]:
    data = row.to_dict()
    return data


def explain_event(features: dict[str, Any], assessment: dict[str, Any], *, use_gpt: bool, api_key: str | None) -> dict[str, str]:
    if use_gpt and api_key:
        try:
            return gpt_explainer.generate_explanation(
                features, assessment["risk_score"], assessment["risk_category"], api_key
            )
        except Exception as exc:  # noqa: BLE001 - deliberate broad fallback
            logger.warning("GPT explanation failed (%s); falling back to rule-based engine.", exc)

    return rule_explainer.generate_explanation(
        features,
        assessment["risk_score"],
        assessment["risk_category"],
        assessment["rule_adjustments"],
    )


def assess_features(features: dict[str, Any], *, use_gpt: bool = False, api_key: str | None = None) -> dict[str, Any]:
    """Score one feature row and attach a plain-English explanation."""
    assessment = score_event({k: features.get(k) for k in FEATURE_COLUMNS} | {
        "protocol": features.get("protocol"),
        "source_ip": features.get("source_ip"),
        "destination_ip": features.get("destination_ip"),
        "destination_port": features.get("destination_port"),
        "is_business_hours": features.get("is_business_hours"),
        "is_night": features.get("is_night"),
        "is_dangerous_port": features.get("is_dangerous_port"),
        "unique_destinations_60min": features.get("unique_destinations_60min"),
        "requests_last_60min": features.get("requests_last_60min"),
        "deviation_score": features.get("deviation_score"),
    })
    explanation = explain_event(features, assessment, use_gpt=use_gpt, api_key=api_key)
    assessment["explanation"] = explanation
    return assessment


def run_assessment_pipeline(
    *,
    limit: int = 500,
    event_ids: list[int] | None = None,
    use_gpt: bool = False,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """Run pipeline -> score -> explain -> persist for a batch of events.

    Returns a list of {event_id, risk_score, risk_category, explanation}.
    """
    features_df, rejected = run_pipeline(limit=limit, event_ids=event_ids)
    if rejected:
        logger.warning("Pipeline rejected %d malformed event(s).", len(rejected))

    results = []
    for _, row in features_df.iterrows():
        features = _feature_row_to_dict(row)
        event_id = features.get("event_id")
        if event_id is None:
            continue

        assessment = assess_features(features, use_gpt=use_gpt, api_key=api_key)
        saved = models.create_risk_assessment(int(event_id), assessment)
        models.mark_event_processed(int(event_id))

        results.append({
            "event_id": int(event_id),
            "risk_score": assessment["risk_score"],
            "risk_category": assessment["risk_category"],
            "explanation": assessment["explanation"],
            "scoring_method": assessment.get("scoring_method"),
            "assessment_id": saved.get("assessment_id") if saved else None,
        })

    logger.info("AI engine assessed %d event(s).", len(results))
    return results
