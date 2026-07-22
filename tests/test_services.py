"""Unit tests for service-layer business logic."""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

import pytest

from backend.exceptions import NotFoundError
from backend.services import allow_device, apply_decision, assess_event, block_device

DEVICE_ID = "550e8400-e29b-41d4-a716-446655440000"


@patch("backend.services.models.create_decision")
@patch("backend.services.models.update_device_flags")
@patch("backend.services.models.require_device")
def test_apply_decision_block(mock_require, mock_update, mock_create):
    mock_require.return_value = {"device_id": UUID(DEVICE_ID), "ip_address": "10.0.0.1"}
    mock_update.return_value = {"device_id": UUID(DEVICE_ID), "is_blocked": True}
    mock_create.return_value = {"decision_id": 1, "action": "block"}

    result = apply_decision(ip_address="10.0.0.1", action="block")
    assert result["decision"]["action"] == "block"
    mock_update.assert_called_once()


@patch("backend.services.models.get_device_by_id", return_value=None)
def test_allow_device_not_found(mock_get):
    with pytest.raises(NotFoundError):
        allow_device(device_id=DEVICE_ID)


@patch("backend.services.models.get_risk_by_event_id", return_value={"assessment_id": 1})
@patch("backend.services.models.require_event")
def test_assess_event_returns_existing(mock_require, mock_existing):
    mock_require.return_value = {"event_id": 1}
    result = assess_event(event_id=1, force_reassess=False)
    assert result["created"] is False


@patch("backend.services.models.mark_event_processed")
@patch("backend.services.models.create_risk_assessment")
@patch("backend.services.models.compute_rule_based_risk")
@patch("backend.services.models.get_risk_by_event_id", return_value=None)
@patch("backend.services.models.require_event")
def test_assess_event_creates_new(
    mock_require, mock_get_risk, mock_compute, mock_create, mock_mark
):
    mock_require.return_value = {"event_id": 1, "source_ip": "10.0.0.1"}
    mock_compute.return_value = {
        "risk_score": 40,
        "risk_category": "Medium",
        "anomaly_score": -0.1,
        "ml_score": None,
        "rule_adjustments": [],
        "explanation": {"observation": "x", "context": "y", "recommendation": "z"},
    }
    mock_create.return_value = {"assessment_id": 10, "event_id": 1}

    result = assess_event(event_id=1)
    assert result["created"] is True
    mock_mark.assert_called_once_with(1)


@patch("backend.services.apply_decision")
def test_block_device_by_ip(mock_apply):
    mock_apply.return_value = {"decision": {"action": "always_block"}, "device": {}}

    block_device(ip_address="10.0.0.5", permanent=True)
    mock_apply.assert_called_once()
    assert mock_apply.call_args.kwargs["action"] == "always_block"
