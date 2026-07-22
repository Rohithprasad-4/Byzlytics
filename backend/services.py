"""Business logic for security decisions and risk assessment."""

from __future__ import annotations

import logging
from typing import Any

from backend import decision_engine, models
from backend.exceptions import NotFoundError

logger = logging.getLogger(__name__)


def apply_decision(
    *,
    ip_address: str,
    action: str,
    device_id: str | None = None,
    reason: str | None = None,
    assessment_id: int | None = None,
    triggered_by: str = "api",
) -> dict[str, Any]:
    """Persist a user decision and update device trust/block flags."""
    return decision_engine.apply_decision(
        ip_address=ip_address,
        action=action,
        device_id=device_id,
        reason=reason,
        assessment_id=assessment_id,
        triggered_by=triggered_by,
    )


def revoke_decisions_for_ip(ip_address: str) -> dict[str, Any]:
    return decision_engine.revoke_decisions(ip_address)


def get_permitted_status(ip_address: str) -> dict[str, Any]:
    return decision_engine.is_ip_permitted(ip_address)


def allow_device(
    *,
    ip_address: str | None = None,
    device_id: str | None = None,
    reason: str | None = None,
    permanent: bool = False,
) -> dict[str, Any]:
    if not ip_address and device_id:
        device = models.get_device_by_id(device_id)
        if device is None:
            raise NotFoundError(f"Device {device_id} not found.")
        ip_address = str(device["ip_address"])

    if not ip_address:
        raise NotFoundError("ip_address could not be resolved.")

    action = "always_allow" if permanent else "allow"
    return apply_decision(
        ip_address=ip_address,
        action=action,
        device_id=device_id,
        reason=reason,
        triggered_by="allow_endpoint",
    )


def block_device(
    *,
    ip_address: str | None = None,
    device_id: str | None = None,
    reason: str | None = None,
    permanent: bool = False,
) -> dict[str, Any]:
    if not ip_address and device_id:
        device = models.get_device_by_id(device_id)
        if device is None:
            raise NotFoundError(f"Device {device_id} not found.")
        ip_address = str(device["ip_address"])

    if not ip_address:
        raise NotFoundError("ip_address could not be resolved.")

    action = "always_block" if permanent else "block"
    return apply_decision(
        ip_address=ip_address,
        action=action,
        device_id=device_id,
        reason=reason,
        triggered_by="block_endpoint",
    )


def assess_event(*, event_id: int, force_reassess: bool = False) -> dict[str, Any]:
    """Run risk assessment for a single event and persist results.

    Prefers the full AI engine pipeline (pipeline -> Isolation Forest ->
    rule bonuses -> GPT/rule explanation); falls back to the simpler
    in-process rule scorer in backend.models if the ML/AI packages or
    their dependencies (pandas, scikit-learn, openai) aren't available.
    """
    event = models.require_event(event_id)

    existing = models.get_risk_by_event_id(event_id)
    if existing and not force_reassess:
        return {"assessment": existing, "created": False}

    if existing and force_reassess:
        from backend import database as db

        db.execute("DELETE FROM risk_assessment WHERE event_id = %s", (event_id,))

    try:
        from ai_engine.ai_engine import run_assessment_pipeline

        results = run_assessment_pipeline(event_ids=[event_id])
        if results:
            assessment = models.get_risk_by_event_id(event_id)
            return {"assessment": assessment, "created": True}
    except ImportError as exc:
        logger.warning("AI engine dependencies unavailable (%s); using rule-based fallback.", exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI engine pipeline failed (%s); using rule-based fallback.", exc)

    assessment_data = models.compute_rule_based_risk(event)
    assessment = models.create_risk_assessment(event_id, assessment_data)
    models.mark_event_processed(event_id)

    return {"assessment": assessment, "created": True}


def run_bulk_assessment(
    *,
    event_ids: list[int] | None = None,
    limit: int = 500,
    use_gpt: bool = False,
) -> list[dict[str, Any]]:
    """Run the AI engine pipeline over multiple unprocessed events at once."""
    from backend.config import load_config

    api_key = load_config().openai_api_key

    try:
        from ai_engine.ai_engine import run_assessment_pipeline

        return run_assessment_pipeline(
            event_ids=event_ids,
            limit=limit,
            use_gpt=use_gpt,
            api_key=api_key,
        )
    except ImportError as exc:
        logger.warning("AI engine dependencies unavailable (%s); falling back per-event.", exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bulk AI engine pipeline failed (%s); falling back per-event.", exc)

    # Fallback: rule-score every unprocessed event individually.
    unprocessed = models.list_events(limit=limit, offset=0) if not event_ids else [
        models.require_event(eid) for eid in event_ids
    ]
    results = []
    for event in unprocessed:
        if event.get("processed"):
            continue
        assessment_data = models.compute_rule_based_risk(event)
        saved = models.create_risk_assessment(event["event_id"], assessment_data)
        models.mark_event_processed(event["event_id"])
        results.append({
            "event_id": event["event_id"],
            "risk_score": assessment_data["risk_score"],
            "risk_category": assessment_data["risk_category"],
            "explanation": assessment_data["explanation"],
            "scoring_method": "rule_only_fallback",
            "assessment_id": saved.get("assessment_id") if saved else None,
        })
    return results
