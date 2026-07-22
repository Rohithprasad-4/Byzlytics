"""API integration tests with mocked data layer."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest

from backend.exceptions import NotFoundError

DEVICE_ID = "550e8400-e29b-41d4-a716-446655440000"
SAMPLE_DEVICE = {
    "device_id": UUID(DEVICE_ID),
    "ip_address": "192.168.1.10",
    "mac_address": "00:1A:2B:3C:4D:5E",
    "device_type": "workstation",
    "hostname": "pc-01",
    "first_seen": datetime(2026, 7, 16, 10, 0, tzinfo=timezone.utc),
    "last_seen": datetime(2026, 7, 16, 11, 0, tzinfo=timezone.utc),
    "is_trusted": False,
    "is_blocked": False,
    "notes": None,
    "max_risk_score": Decimal("30"),
    "avg_risk_score": Decimal("15"),
    "high_risk_events": 0,
}

SAMPLE_EVENT = {
    "event_id": 1,
    "device_id": UUID(DEVICE_ID),
    "timestamp": datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
    "protocol": "TCP",
    "source_ip": "192.168.1.10",
    "destination_ip": "8.8.8.8",
    "source_port": 45000,
    "destination_port": 443,
    "packet_size": 512,
    "processed": False,
    "capture_iface": "eth0",
    "raw_metadata": {},
}

SAMPLE_RISK = {
    "assessment_id": 1,
    "event_id": 1,
    "risk_score": Decimal("45"),
    "risk_category": "Medium",
    "explanation": {
        "observation": "TCP traffic observed",
        "context": "Moderate risk",
        "recommendation": "Monitor",
    },
    "anomaly_score": Decimal("-0.15"),
    "ml_score": None,
    "rule_adjustments": [],
    "assessed_at": datetime(2026, 7, 16, 12, 5, tzinfo=timezone.utc),
    "source_ip": "192.168.1.10",
    "destination_ip": "8.8.8.8",
    "protocol": "TCP",
    "device_id": UUID(DEVICE_ID),
}

SAMPLE_DECISION = {
    "decision_id": 1,
    "device_id": UUID(DEVICE_ID),
    "ip_address": "192.168.1.10",
    "action": "block",
    "reason": "Suspicious",
    "triggered_by": "api",
    "assessment_id": 1,
    "decided_at": datetime(2026, 7, 16, 12, 10, tzinfo=timezone.utc),
    "expires_at": None,
    "is_active": True,
}

SAMPLE_STATS = {
    "summary_date": datetime(2026, 7, 16).date(),
    "total_devices": 3,
    "active_devices": 2,
    "total_events": 100,
    "dns_events": 30,
    "tcp_events": 60,
    "icmp_events": 10,
    "low_risk_count": 70,
    "medium_risk_count": 20,
    "high_risk_count": 10,
    "blocked_devices": 1,
    "blocked_requests": 5,
    "suspicious_devices": 2,
    "avg_risk_score": Decimal("25.5"),
    "peak_hour": 14,
    "top_risky_ips": [],
    "hourly_distribution": {"12": 20},
    "protocol_distribution": {"TCP": 60},
    "live": {},
}


class TestHealthEndpoint:
    @patch("backend.database.check_health", return_value={
        "database": "connected",
        "database_name": "network_security",
        "server_time": "2026-07-16T12:00:00",
    })
    def test_health_connected(self, mock_health, client):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.get_json()
        assert body["status"] == "success"
        assert body["data"]["status"] == "healthy"

    @patch("backend.database.check_health", return_value={"database": "disconnected"})
    def test_health_degraded(self, mock_health, client):
        response = client.get("/health")
        assert response.status_code == 503
        assert response.get_json()["data"]["status"] == "degraded"


class TestDevicesEndpoint:
    @patch("backend.routes.models.list_devices", return_value=[SAMPLE_DEVICE])
    @patch("backend.routes.models.count_devices", return_value=1)
    def test_get_devices(self, mock_count, mock_list, client):
        response = client.get("/devices?page=1&limit=10")
        assert response.status_code == 200
        body = response.get_json()
        assert body["status"] == "success"
        assert len(body["data"]["items"]) == 1
        assert body["data"]["pagination"]["total"] == 1

    @patch("backend.routes.models.get_device_by_id", return_value=SAMPLE_DEVICE)
    def test_get_device_by_id(self, mock_get, client):
        response = client.get(f"/devices/{DEVICE_ID}")
        assert response.status_code == 200
        assert response.get_json()["data"]["ip_address"] == "192.168.1.10"

    @patch("backend.routes.models.get_device_by_id", return_value=None)
    def test_get_device_not_found(self, mock_get, client):
        response = client.get(f"/devices/{DEVICE_ID}")
        assert response.status_code == 404


class TestEventsEndpoint:
    @patch("backend.routes.models.list_events", return_value=[SAMPLE_EVENT])
    @patch("backend.routes.models.count_events", return_value=1)
    def test_get_events(self, mock_count, mock_list, client):
        response = client.get("/events?protocol=TCP")
        assert response.status_code == 200
        assert response.get_json()["data"]["items"][0]["protocol"] == "TCP"

    @patch("backend.routes.models.get_event_by_id", return_value=SAMPLE_EVENT)
    def test_get_event_by_id(self, mock_get, client):
        response = client.get("/events/1")
        assert response.status_code == 200
        assert response.get_json()["data"]["event_id"] == 1

    @patch("backend.routes.models.get_event_by_id", return_value=None)
    def test_get_event_not_found(self, mock_get, client):
        response = client.get("/events/999")
        assert response.status_code == 404


class TestRisksEndpoint:
    @patch("backend.routes.models.list_risks", return_value=[SAMPLE_RISK])
    @patch("backend.routes.models.count_risks", return_value=1)
    def test_get_risks(self, mock_count, mock_list, client):
        response = client.get("/risks?risk_category=Medium")
        assert response.status_code == 200
        assert response.get_json()["data"]["items"][0]["risk_category"] == "Medium"


class TestStatsEndpoint:
    @patch("backend.routes.models.build_stats_payload", return_value=SAMPLE_STATS)
    def test_get_stats(self, mock_stats, client):
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.get_json()["data"]
        assert data["total_devices"] == 3
        assert data["high_risk_count"] == 10


class TestDecisionsEndpoint:
    @patch("backend.routes.models.list_decisions", return_value=[SAMPLE_DECISION])
    @patch("backend.routes.models.count_decisions", return_value=1)
    def test_get_decisions(self, mock_count, mock_list, client):
        response = client.get("/decisions")
        assert response.status_code == 200
        assert response.get_json()["data"]["items"][0]["action"] == "block"


class TestDecideEndpoint:
    @patch("backend.routes.services.apply_decision")
    def test_post_decide(self, mock_apply, client):
        mock_apply.return_value = {
            "decision": SAMPLE_DECISION,
            "device": {**SAMPLE_DEVICE, "is_blocked": True},
        }
        response = client.post("/decide", json={
            "ip_address": "192.168.1.10",
            "action": "block",
            "reason": "Test block",
        })
        assert response.status_code == 201
        assert response.get_json()["data"]["decision"]["action"] == "block"

    def test_post_decide_validation_error(self, client):
        response = client.post("/decide", json={"action": "block"})
        assert response.status_code == 400
        assert response.get_json()["status"] == "error"


class TestAllowBlockEndpoints:
    @patch("backend.routes.services.allow_device")
    def test_post_allow(self, mock_allow, client):
        mock_allow.return_value = {
            "decision": {**SAMPLE_DECISION, "action": "allow"},
            "device": {**SAMPLE_DEVICE, "is_trusted": True},
        }
        response = client.post("/allow", json={"ip_address": "192.168.1.10"})
        assert response.status_code == 201
        assert response.get_json()["message"] == "Device allowed successfully."

    @patch("backend.routes.services.block_device")
    def test_post_block(self, mock_block, client):
        mock_block.return_value = {
            "decision": SAMPLE_DECISION,
            "device": {**SAMPLE_DEVICE, "is_blocked": True},
        }
        response = client.post("/block", json={"ip_address": "192.168.1.10", "permanent": True})
        assert response.status_code == 201
        mock_block.assert_called_once()

    @patch("backend.routes.services.block_device", side_effect=NotFoundError("Device not found"))
    def test_post_block_not_found(self, mock_block, client):
        response = client.post("/block", json={"device_id": DEVICE_ID})
        assert response.status_code == 404


class TestAssessEndpoint:
    @patch("backend.routes.services.assess_event")
    def test_post_assess_create(self, mock_assess, client):
        mock_assess.return_value = {"assessment": SAMPLE_RISK, "created": True}
        response = client.post("/assess", json={"event_id": 1})
        assert response.status_code == 201
        assert response.get_json()["data"]["created"] is True

    @patch("backend.routes.services.assess_event")
    def test_post_assess_existing(self, mock_assess, client):
        mock_assess.return_value = {"assessment": SAMPLE_RISK, "created": False}
        response = client.post("/assess", json={"event_id": 1})
        assert response.status_code == 200

    def test_post_assess_invalid_payload(self, client):
        response = client.post("/assess", json={})
        assert response.status_code == 400


class TestReportEndpoint:
    @patch("backend.routes.generate_report")
    def test_download_report(self, mock_report, client):
        mock_report.return_value = (b"%PDF-1.4 fake", "securegate_report_2026-07-16.pdf")
        response = client.get("/report/download?date=2026-07-16")
        assert response.status_code == 200
        assert response.mimetype == "application/pdf"
        assert b"PDF" in response.data


class TestErrorHandling:
    def test_not_found_route(self, client):
        response = client.get("/nonexistent")
        assert response.status_code == 404
        assert response.get_json()["status"] == "error"

    def test_method_not_allowed(self, client):
        response = client.delete("/health")
        assert response.status_code == 405

    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert response.get_json()["data"]["version"] == "1.0.0"
