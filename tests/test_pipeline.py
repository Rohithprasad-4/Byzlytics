"""Unit tests for pipeline.validator, pipeline.cleaner, pipeline.transformer.

Stages 1 (collect) and 5 (enrich) require a live PostgreSQL connection
and are covered by integration tests instead.
"""

from __future__ import annotations

import pandas as pd
import pytest

from pipeline.cleaner import clean_events
from pipeline.transformer import transform_events
from pipeline.validator import validate_events

RAW_ROWS = [
    {
        "event_id": 1, "device_id": None, "timestamp": "2026-01-15T02:30:00Z",
        "protocol": "dns", "source_ip": "192.168.1.25", "destination_ip": "8.8.8.8",
        "source_port": 51000, "destination_port": 53, "packet_size": 128,
    },
    {
        "event_id": 2, "device_id": None, "timestamp": "2026-01-15T14:00:00Z",
        "protocol": "tcp", "source_ip": "192.168.1.30", "destination_ip": "10.0.0.5",
        "source_port": 50111, "destination_port": 3389, "packet_size": 64,
    },
]


class TestValidator:
    def test_valid_rows_pass_through(self):
        df = pd.DataFrame(RAW_ROWS)
        valid, rejected = validate_events(df)
        assert len(valid) == 2
        assert rejected == []

    def test_invalid_ip_is_rejected(self):
        rows = RAW_ROWS + [{**RAW_ROWS[0], "event_id": 3, "source_ip": "not-an-ip"}]
        df = pd.DataFrame(rows)
        valid, rejected = validate_events(df)
        assert len(valid) == 2
        assert len(rejected) == 1
        assert rejected[0]["event_id"] == 3

    def test_negative_packet_size_is_rejected(self):
        rows = RAW_ROWS + [{**RAW_ROWS[0], "event_id": 4, "packet_size": -10}]
        df = pd.DataFrame(rows)
        valid, rejected = validate_events(df)
        assert len(valid) == 2
        assert any(r["event_id"] == 4 for r in rejected)

    def test_unrecognised_protocol_is_rejected(self):
        rows = RAW_ROWS + [{**RAW_ROWS[0], "event_id": 5, "protocol": "ftp"}]
        df = pd.DataFrame(rows)
        valid, rejected = validate_events(df)
        assert any(r["event_id"] == 5 for r in rejected)

    def test_empty_dataframe_returns_empty(self):
        valid, rejected = validate_events(pd.DataFrame())
        assert valid.empty
        assert rejected == []


class TestCleaner:
    def test_protocol_uppercased(self):
        df = pd.DataFrame(RAW_ROWS)
        cleaned = clean_events(df)
        assert set(cleaned["protocol"]) == {"DNS", "TCP"}

    def test_ports_coerced_to_int(self):
        df = pd.DataFrame(RAW_ROWS)
        cleaned = clean_events(df)
        assert cleaned["source_port"].dtype.kind == "i"

    def test_duplicate_rows_removed(self):
        df = pd.DataFrame(RAW_ROWS + [RAW_ROWS[0]])
        cleaned = clean_events(df)
        assert len(cleaned) == 2


class TestTransformer:
    def test_one_hot_protocol_sums_to_one(self):
        df = clean_events(pd.DataFrame(RAW_ROWS))
        transformed = transform_events(df)
        sums = (
            transformed["protocol_dns"]
            + transformed["protocol_tcp"]
            + transformed["protocol_icmp"]
        )
        assert (sums == 1).all()

    def test_dangerous_port_flagged(self):
        df = clean_events(pd.DataFrame(RAW_ROWS))
        transformed = transform_events(df)
        row = transformed[transformed["destination_port"] == 3389].iloc[0]
        assert row["is_dangerous_port"] == 1

    def test_safe_port_not_flagged(self):
        safe_row = [{**RAW_ROWS[0], "destination_port": 51234}]
        df = clean_events(pd.DataFrame(safe_row))
        transformed = transform_events(df)
        assert transformed.iloc[0]["is_dangerous_port"] == 0

    def test_night_activity_flagged(self):
        df = clean_events(pd.DataFrame(RAW_ROWS))
        transformed = transform_events(df)
        night_row = transformed[transformed["hour_of_day"] == 2].iloc[0]
        assert night_row["is_night"] == 1
        assert night_row["is_business_hours"] == 0
