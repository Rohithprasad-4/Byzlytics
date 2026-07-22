"""Unit tests for model-layer risk computation and helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.models import _risk_category, compute_rule_based_risk


def test_risk_category_boundaries():
    assert _risk_category(0) == "Low"
    assert _risk_category(30) == "Low"
    assert _risk_category(31) == "Medium"
    assert _risk_category(60) == "Medium"
    assert _risk_category(61) == "High"
    assert _risk_category(100) == "High"


def test_compute_rule_based_risk_dangerous_port(monkeypatch):
    monkeypatch.setattr(
        "backend.models.get_recent_event_stats_for_ip",
        lambda *_args, **_kwargs: {
            "requests_in_window": 5,
            "unique_destinations": 2,
            "dns_count_in_window": 0,
            "tcp_count_in_window": 5,
            "icmp_count_in_window": 0,
            "avg_packet_size_ip": 500,
        },
    )
    event = {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "destination_port": 22,
        "protocol": "TCP",
        "packet_size": 500,
        "timestamp": datetime(2026, 7, 16, 14, 0, tzinfo=timezone.utc),
    }
    result = compute_rule_based_risk(event)
    assert result["risk_score"] >= 35
    assert result["risk_category"] in {"Medium", "High"}
    assert any(a["rule"] == "dangerous_port" for a in result["rule_adjustments"])
    assert "observation" in result["explanation"]


def test_compute_rule_based_risk_night_activity(monkeypatch):
    monkeypatch.setattr(
        "backend.models.get_recent_event_stats_for_ip",
        lambda *_args, **_kwargs: {
            "requests_in_window": 1,
            "unique_destinations": 1,
            "dns_count_in_window": 0,
            "tcp_count_in_window": 1,
            "icmp_count_in_window": 0,
            "avg_packet_size_ip": 100,
        },
    )
    event = {
        "source_ip": "192.168.1.50",
        "destination_ip": "8.8.8.8",
        "destination_port": 9999,
        "protocol": "TCP",
        "packet_size": 100,
        "timestamp": datetime(2026, 7, 16, 2, 0, tzinfo=timezone.utc),
    }
    result = compute_rule_based_risk(event)
    assert any(a["rule"] == "night_activity" for a in result["rule_adjustments"])
