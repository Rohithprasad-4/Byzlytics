"""Unit tests for API serializers."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from backend.serializers import (
    serialize_decision,
    serialize_device,
    serialize_event,
    serialize_pagination,
    serialize_risk,
    serialize_stats,
)


def test_serialize_device():
    row = {
        "device_id": UUID("550e8400-e29b-41d4-a716-446655440000"),
        "ip_address": "192.168.1.10",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "device_type": "workstation",
        "hostname": "pc-01",
        "first_seen": datetime(2026, 7, 16, 10, 0, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 7, 16, 11, 0, tzinfo=timezone.utc),
        "is_trusted": True,
        "is_blocked": False,
        "notes": None,
        "max_risk_score": Decimal("45.50"),
        "avg_risk_score": Decimal("22.10"),
        "high_risk_events": 1,
    }
    result = serialize_device(row)
    assert result["device_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert result["ip_address"] == "192.168.1.10"
    assert result["is_trusted"] is True
    assert result["max_risk_score"] == 45.5


def test_serialize_event():
    row = {
        "event_id": 100,
        "device_id": None,
        "timestamp": datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
        "protocol": "TCP",
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 54321,
        "destination_port": 443,
        "packet_size": 512,
        "processed": False,
        "capture_iface": "eth0",
        "raw_metadata": {"ttl": 64},
    }
    result = serialize_event(row)
    assert result["event_id"] == 100
    assert result["protocol"] == "TCP"
    assert result["raw_metadata"] == {"ttl": 64}


def test_serialize_risk():
    row = {
        "assessment_id": 1,
        "event_id": 100,
        "risk_score": Decimal("72.5"),
        "risk_category": "High",
        "explanation": {"observation": "test", "context": "ctx", "recommendation": "block"},
        "anomaly_score": Decimal("-0.25"),
        "ml_score": None,
        "rule_adjustments": [{"rule": "dangerous_port", "delta": 15}],
        "assessed_at": datetime(2026, 7, 16, 12, 5, tzinfo=timezone.utc),
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "protocol": "TCP",
        "device_id": None,
    }
    result = serialize_risk(row)
    assert result["risk_category"] == "High"
    assert result["explanation"]["recommendation"] == "block"


def test_serialize_decision():
    row = {
        "decision_id": 5,
        "device_id": UUID("550e8400-e29b-41d4-a716-446655440000"),
        "ip_address": "192.168.1.20",
        "action": "block",
        "reason": "High risk",
        "triggered_by": "api",
        "assessment_id": 1,
        "decided_at": datetime(2026, 7, 16, 12, 10, tzinfo=timezone.utc),
        "expires_at": None,
        "is_active": True,
    }
    result = serialize_decision(row)
    assert result["action"] == "block"
    assert result["is_active"] is True


def test_serialize_stats():
    row = {
        "summary_date": datetime(2026, 7, 16).date(),
        "total_devices": 10,
        "active_devices": 8,
        "total_events": 1000,
        "dns_events": 400,
        "tcp_events": 500,
        "icmp_events": 100,
        "low_risk_count": 700,
        "medium_risk_count": 200,
        "high_risk_count": 100,
        "blocked_devices": 2,
        "blocked_requests": 15,
        "suspicious_devices": 3,
        "avg_risk_score": Decimal("28.5"),
        "peak_hour": 14,
        "top_risky_ips": [],
        "hourly_distribution": {"10": 50},
        "protocol_distribution": {"TCP": 500},
        "live": {"devices": {"total_devices": 10}},
    }
    result = serialize_stats(row)
    assert result["total_devices"] == 10
    assert result["live"]["devices"]["total_devices"] == 10


def test_serialize_pagination():
    result = serialize_pagination([{"id": 1}], page=1, limit=10, total=25)
    assert result["pagination"]["total_pages"] == 3
    assert result["pagination"]["has_next"] is True
    assert len(result["items"]) == 1
