"""Unit tests for request validators."""

from __future__ import annotations

import pytest

from backend.exceptions import ValidationError
from backend.validators import (
    validate_allow_block_payload,
    validate_assess_payload,
    validate_decide_payload,
    validate_ip_address,
    validate_pagination,
    validate_report_date,
    validate_uuid,
)


class TestPagination:
    def test_defaults(self):
        result = validate_pagination({})
        assert result == {"page": 1, "limit": 50, "offset": 0}

    def test_custom_page_limit(self):
        result = validate_pagination({"page": "2", "limit": "25"})
        assert result["page"] == 2
        assert result["limit"] == 25
        assert result["offset"] == 25

    def test_invalid_page(self):
        with pytest.raises(ValidationError):
            validate_pagination({"page": "0"})

    def test_limit_too_high(self):
        with pytest.raises(ValidationError):
            validate_pagination({"limit": "500"})


class TestIPAddress:
    def test_valid_ipv4(self):
        assert validate_ip_address("192.168.1.10") == "192.168.1.10"

    def test_invalid_ip(self):
        with pytest.raises(ValidationError):
            validate_ip_address("not-an-ip")


class TestUUID:
    def test_valid_uuid(self):
        value = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_uuid(value) == value

    def test_invalid_uuid(self):
        with pytest.raises(ValidationError):
            validate_uuid("bad-uuid")


class TestDecidePayload:
    def test_valid_payload(self):
        payload = validate_decide_payload({
            "ip_address": "10.0.0.5",
            "action": "block",
            "reason": "Suspicious scanning",
        })
        assert payload["ip_address"] == "10.0.0.5"
        assert payload["action"] == "block"

    def test_missing_fields(self):
        with pytest.raises(ValidationError):
            validate_decide_payload({})

    def test_invalid_action(self):
        with pytest.raises(ValidationError):
            validate_decide_payload({
                "ip_address": "10.0.0.5",
                "action": "nuke",
            })


class TestAllowBlockPayload:
    def test_ip_only(self):
        payload = validate_allow_block_payload({"ip_address": "10.0.0.1"})
        assert payload["ip_address"] == "10.0.0.1"

    def test_device_id_only(self):
        payload = validate_allow_block_payload({
            "device_id": "550e8400-e29b-41d4-a716-446655440000",
        })
        assert "device_id" in payload

    def test_requires_identifier(self):
        with pytest.raises(ValidationError):
            validate_allow_block_payload({})


class TestAssessPayload:
    def test_valid(self):
        payload = validate_assess_payload({"event_id": 42})
        assert payload["event_id"] == 42
        assert payload["force_reassess"] is False

    def test_force_reassess(self):
        payload = validate_assess_payload({"event_id": 1, "force_reassess": True})
        assert payload["force_reassess"] is True

    def test_missing_event_id(self):
        with pytest.raises(ValidationError):
            validate_assess_payload({})


class TestReportDate:
    def test_valid_date(self):
        assert validate_report_date("2026-07-16") == "2026-07-16"

    def test_none_allowed(self):
        assert validate_report_date(None) is None

    def test_invalid_format(self):
        with pytest.raises(ValidationError):
            validate_report_date("16-07-2026")
