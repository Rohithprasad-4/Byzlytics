"""Phase 10 — Priority-based user decision engine.

Decision priority (highest wins): always_block > always_allow > block > allow.
Setting an "always_*" decision deactivates all prior decisions for that
IP so exactly one decision is authoritative at a time. All writes run
inside a single DB transaction (see backend.database.get_cursor) so a
device's flags and its decision record never diverge.
"""

from __future__ import annotations

from typing import Any

from backend import models
from backend.exceptions import NotFoundError

PRIORITY = {"always_block": 3, "always_allow": 2, "block": 1, "allow": 0}


def resolve_effective_action(actions: list[str]) -> str | None:
    """Given multiple active actions for an IP, return the highest-priority one."""
    if not actions:
        return None
    return max(actions, key=lambda a: PRIORITY.get(a, -1))


def apply_decision(
    *,
    ip_address: str,
    action: str,
    device_id: str | None = None,
    reason: str | None = None,
    assessment_id: int | None = None,
    triggered_by: str = "api",
) -> dict[str, Any]:
    """Persist a decision and update device trust/block flags atomically."""
    device = models.require_device(device_id, ip_address)
    resolved_device_id = str(device["device_id"])

    # An "always_*" decision permanently supersedes prior decisions for this IP.
    if action in {"always_allow", "always_block"}:
        models.deactivate_decisions_for_ip(ip_address)

    is_trusted = None
    is_blocked = None
    if action in {"allow", "always_allow"}:
        is_trusted = True
        is_blocked = False
    elif action in {"block", "always_block"}:
        is_trusted = False
        is_blocked = True

    updated_device = models.update_device_flags(
        device_id=resolved_device_id,
        ip_address=ip_address,
        is_trusted=is_trusted,
        is_blocked=is_blocked,
    )

    decision = models.create_decision(
        ip_address=ip_address,
        action=action,
        device_id=resolved_device_id,
        reason=reason,
        assessment_id=assessment_id,
        triggered_by=triggered_by,
    )

    return {"decision": decision, "device": updated_device}


def revoke_decisions(ip_address: str) -> dict[str, Any]:
    """Deactivate all active decisions for an IP and clear device flags."""
    models.deactivate_decisions_for_ip(ip_address)
    device = models.get_device_by_ip(ip_address)
    if device is None:
        raise NotFoundError(f"No device found for {ip_address}.")
    return models.update_device_flags(
        device_id=str(device["device_id"]),
        ip_address=ip_address,
        is_trusted=False,
        is_blocked=False,
    )


def is_ip_permitted(ip_address: str) -> dict[str, Any]:
    """Used by the capture layer / GET /permitted/<ip>: is this IP allowed to generate events?"""
    decision = models.get_active_decision_for_ip(ip_address)
    if decision is None:
        return {"is_permitted": True, "decision": None}
    permitted = decision["action"] not in ("block", "always_block")
    return {"is_permitted": permitted, "decision": decision}
