"""Request and query parameter validation."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from uuid import UUID

from backend.exceptions import ValidationError

DECISION_ACTIONS = frozenset({"allow", "block", "always_allow", "always_block"})
RISK_CATEGORIES = frozenset({"Low", "Medium", "High"})
PROTOCOLS = frozenset({"DNS", "TCP", "ICMP", "OTHER"})
DEVICE_TYPES = frozenset({
    "workstation", "server", "mobile", "iot", "router", "printer", "unknown"
})

MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50


def _require_dict(payload: Any, field_name: str = "request body") -> dict:
    if not isinstance(payload, dict):
        raise ValidationError(f"Invalid {field_name}: expected JSON object.")
    return payload


def validate_pagination(args: dict[str, str]) -> dict[str, int]:
    """Validate page/limit query parameters."""
    try:
        page = int(args.get("page", 1))
        limit = int(args.get("limit", DEFAULT_PAGE_LIMIT))
    except (TypeError, ValueError) as exc:
        raise ValidationError("page and limit must be integers.") from exc

    if page < 1:
        raise ValidationError("page must be >= 1.")
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ValidationError(f"limit must be between 1 and {MAX_PAGE_LIMIT}.")

    return {"page": page, "limit": limit, "offset": (page - 1) * limit}


def validate_ip_address(value: str, field_name: str = "ip_address") -> str:
    if not value or not isinstance(value, str):
        raise ValidationError(f"{field_name} is required.")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError(f"Invalid {field_name}: {value}") from exc


def validate_uuid(value: str, field_name: str = "device_id") -> str:
    if not value:
        raise ValidationError(f"{field_name} is required.")
    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"Invalid {field_name}: {value}") from exc


def validate_optional_protocol(value: str | None) -> str | None:
    if value is None:
        return None
    protocol = value.strip().upper()
    if protocol not in PROTOCOLS:
        raise ValidationError(f"protocol must be one of: {', '.join(sorted(PROTOCOLS))}")
    return protocol


def validate_optional_risk_category(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in RISK_CATEGORIES:
        raise ValidationError(
            f"risk_category must be one of: {', '.join(sorted(RISK_CATEGORIES))}"
        )
    return value


def validate_decision_action(action: str) -> str:
    if action not in DECISION_ACTIONS:
        raise ValidationError(
            f"action must be one of: {', '.join(sorted(DECISION_ACTIONS))}"
        )
    return action


def validate_decide_payload(payload: Any) -> dict[str, Any]:
    data = _require_dict(payload)
    errors: list[str] = []

    ip_address = data.get("ip_address")
    action = data.get("action")
    device_id = data.get("device_id")
    reason = data.get("reason")
    assessment_id = data.get("assessment_id")

    validated: dict[str, Any] = {}

    if not ip_address:
        errors.append("ip_address is required.")
    else:
        validated["ip_address"] = validate_ip_address(ip_address)

    if not action:
        errors.append("action is required.")
    else:
        validated["action"] = validate_decision_action(action)

    if device_id is not None:
        validated["device_id"] = validate_uuid(device_id)

    if assessment_id is not None:
        try:
            validated["assessment_id"] = int(assessment_id)
        except (TypeError, ValueError):
            errors.append("assessment_id must be an integer.")

    if reason is not None:
        if not isinstance(reason, str) or len(reason) > 2000:
            errors.append("reason must be a string up to 2000 characters.")
        else:
            validated["reason"] = reason.strip()

    if errors:
        raise ValidationError("; ".join(errors))

    return validated


def validate_allow_block_payload(payload: Any) -> dict[str, Any]:
    data = _require_dict(payload)
    errors: list[str] = []
    validated: dict[str, Any] = {}

    ip_address = data.get("ip_address")
    device_id = data.get("device_id")
    reason = data.get("reason")
    permanent = bool(data.get("permanent", False))

    if not ip_address and not device_id:
        errors.append("Either ip_address or device_id is required.")

    if ip_address:
        validated["ip_address"] = validate_ip_address(ip_address)
    if device_id:
        validated["device_id"] = validate_uuid(device_id)
    if reason is not None:
        if not isinstance(reason, str) or len(reason) > 2000:
            errors.append("reason must be a string up to 2000 characters.")
        else:
            validated["reason"] = reason.strip()

    validated["permanent"] = permanent

    if errors:
        raise ValidationError("; ".join(errors))

    return validated


def validate_assess_payload(payload: Any) -> dict[str, Any]:
    data = _require_dict(payload)
    event_id = data.get("event_id")

    if event_id is None:
        raise ValidationError("event_id is required.")

    try:
        event_id_int = int(event_id)
    except (TypeError, ValueError) as exc:
        raise ValidationError("event_id must be an integer.") from exc

    if event_id_int < 1:
        raise ValidationError("event_id must be a positive integer.")

    return {
        "event_id": event_id_int,
        "force_reassess": bool(data.get("force_reassess", False)),
    }


def validate_report_date(value: str | None) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValidationError("date must be in YYYY-MM-DD format.")
    return value


def validate_days_param(value: str | None, *, default: int = 7, maximum: int = 90) -> int:
    if value is None:
        return default
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("days must be an integer.") from exc
    if days < 1 or days > maximum:
        raise ValidationError(f"days must be between 1 and {maximum}.")
    return days


def validate_limit_param(value: str | None, *, default: int = 10, maximum: int = MAX_PAGE_LIMIT) -> int:
    if value is None:
        return default
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("limit must be an integer.") from exc
    if limit < 1 or limit > maximum:
        raise ValidationError(f"limit must be between 1 and {maximum}.")
    return limit


def validate_assess_batch_payload(payload: Any) -> dict[str, Any]:
    data = payload if isinstance(payload, dict) else {}
    event_ids = data.get("event_ids")
    if event_ids is not None:
        if not isinstance(event_ids, list) or not all(isinstance(i, int) for i in event_ids):
            raise ValidationError("event_ids must be a list of integers.")

    limit = data.get("limit", 500)
    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValidationError("limit must be an integer.") from exc

    return {
        "event_ids": event_ids,
        "limit": limit,
        "use_gpt": bool(data.get("use_gpt", False)),
    }
