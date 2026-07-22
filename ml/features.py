"""Canonical 21-column feature schema used across pipeline, ML, and AI engine.

Every stage of the data-engineering pipeline (Phase 5) produces rows that
conform exactly to FEATURE_COLUMNS below, in this order. The Isolation
Forest model (Phase 6) is trained on this matrix, and the AI risk engine
(Phase 7) reads the same columns back out of a scored row to build
human-readable explanations.
"""

from __future__ import annotations

DANGEROUS_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080,
})

FEATURE_COLUMNS: list[str] = [
    "packet_size",
    "source_port",
    "destination_port",
    "protocol_dns",
    "protocol_tcp",
    "protocol_icmp",
    "is_dangerous_port",
    "hour_of_day",
    "day_of_week",
    "is_night",
    "is_business_hours",
    "requests_last_15min",
    "requests_last_60min",
    "unique_destinations_15min",
    "unique_destinations_60min",
    "avg_packet_size_ip",
    "deviation_score",
    "historical_avg_requests_per_hour",
    "request_rate_ratio",
    "is_known_device",
    "is_new_device",
]

assert len(FEATURE_COLUMNS) == 21, "Feature schema must contain exactly 21 columns."
