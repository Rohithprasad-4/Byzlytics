"""Unit tests for capture.parser (dict-based parsing; no live capture needed)."""

from __future__ import annotations

from datetime import datetime, timezone

from capture.parser import parse_packet_dict


class TestParsePacketDict:
    def test_basic_fields_preserved(self):
        raw = {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "dns",
            "source_port": 51000,
            "destination_port": 53,
            "packet_size": 128,
        }
        event = parse_packet_dict(raw)
        assert event["source_ip"] == "192.168.1.10"
        assert event["destination_ip"] == "8.8.8.8"
        assert event["protocol"] == "DNS"
        assert event["packet_size"] == 128

    def test_default_timestamp_is_utc_now(self):
        raw = {"source_ip": "192.168.1.10", "destination_ip": "8.8.8.8", "protocol": "tcp"}
        before = datetime.now(timezone.utc)
        event = parse_packet_dict(raw)
        assert event["timestamp"].tzinfo is not None
        assert event["timestamp"] >= before

    def test_missing_packet_size_defaults_to_64(self):
        raw = {"source_ip": "192.168.1.10", "destination_ip": "8.8.8.8", "protocol": "icmp"}
        event = parse_packet_dict(raw)
        assert event["packet_size"] == 64

    def test_protocol_is_uppercased(self):
        raw = {"source_ip": "192.168.1.10", "destination_ip": "8.8.8.8", "protocol": "tcp"}
        event = parse_packet_dict(raw)
        assert event["protocol"] == "TCP"
