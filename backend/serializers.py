"""Serialize database records into API-friendly dictionaries."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID


def _to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _to_number(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    return value


def _parse_json_field(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def serialize_device(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": str(row["device_id"]) if row.get("device_id") else None,
        "ip_address": str(row["ip_address"]) if row.get("ip_address") else None,
        "mac_address": str(row["mac_address"]) if row.get("mac_address") else None,
        "device_type": row.get("device_type"),
        "hostname": row.get("hostname"),
        "first_seen": _to_iso(row.get("first_seen")),
        "last_seen": _to_iso(row.get("last_seen")),
        "is_trusted": bool(row.get("is_trusted", False)),
        "is_blocked": bool(row.get("is_blocked", False)),
        "notes": row.get("notes"),
        "max_risk_score": _to_number(row.get("max_risk_score")),
        "avg_risk_score": _to_number(row.get("avg_risk_score")),
        "high_risk_events": row.get("high_risk_events"),
    }


def serialize_event(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": row.get("event_id"),
        "device_id": str(row["device_id"]) if row.get("device_id") else None,
        "timestamp": _to_iso(row.get("timestamp")),
        "protocol": row.get("protocol"),
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "destination_ip": str(row["destination_ip"]) if row.get("destination_ip") else None,
        "source_port": row.get("source_port"),
        "destination_port": row.get("destination_port"),
        "packet_size": row.get("packet_size"),
        "processed": bool(row.get("processed", False)),
        "capture_iface": row.get("capture_iface"),
        "raw_metadata": _parse_json_field(row.get("raw_metadata")),
    }


def serialize_risk(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": row.get("assessment_id"),
        "event_id": row.get("event_id"),
        "risk_score": _to_number(row.get("risk_score")),
        "risk_category": row.get("risk_category"),
        "explanation": _parse_json_field(row.get("explanation")),
        "anomaly_score": _to_number(row.get("anomaly_score")),
        "ml_score": _to_number(row.get("ml_score")),
        "rule_adjustments": _parse_json_field(row.get("rule_adjustments")),
        "assessed_at": _to_iso(row.get("assessed_at")),
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "destination_ip": str(row["destination_ip"]) if row.get("destination_ip") else None,
        "protocol": row.get("protocol"),
        "device_id": str(row["device_id"]) if row.get("device_id") else None,
    }


def serialize_decision(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision_id": row.get("decision_id"),
        "device_id": str(row["device_id"]) if row.get("device_id") else None,
        "ip_address": str(row["ip_address"]) if row.get("ip_address") else None,
        "action": row.get("action"),
        "reason": row.get("reason"),
        "triggered_by": row.get("triggered_by"),
        "assessment_id": row.get("assessment_id"),
        "decided_at": _to_iso(row.get("decided_at")),
        "expires_at": _to_iso(row.get("expires_at")),
        "is_active": bool(row.get("is_active", True)),
    }


def serialize_stats(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary_date": _to_iso(row.get("summary_date")),
        "total_devices": row.get("total_devices"),
        "active_devices": row.get("active_devices"),
        "total_events": row.get("total_events"),
        "dns_events": row.get("dns_events"),
        "tcp_events": row.get("tcp_events"),
        "icmp_events": row.get("icmp_events"),
        "low_risk_count": row.get("low_risk_count"),
        "medium_risk_count": row.get("medium_risk_count"),
        "high_risk_count": row.get("high_risk_count"),
        "blocked_devices": row.get("blocked_devices"),
        "blocked_requests": row.get("blocked_requests"),
        "suspicious_devices": row.get("suspicious_devices"),
        "avg_risk_score": _to_number(row.get("avg_risk_score")),
        "peak_hour": row.get("peak_hour"),
        "top_risky_ips": _parse_json_field(row.get("top_risky_ips")),
        "hourly_distribution": _parse_json_field(row.get("hourly_distribution")),
        "protocol_distribution": _parse_json_field(row.get("protocol_distribution")),
        "live": row.get("live", {}),
    }


def serialize_pagination(
    items: list[dict[str, Any]],
    *,
    page: int,
    limit: int,
    total: int,
) -> dict[str, Any]:
    total_pages = max(1, (total + limit - 1) // limit)
    return {
        "items": items,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


def serialize_daily_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary_id": row.get("summary_id"),
        "summary_date": _to_iso(row.get("summary_date")),
        "total_devices": row.get("total_devices"),
        "active_devices": row.get("active_devices"),
        "unique_devices": row.get("unique_devices"),
        "total_events": row.get("total_events"),
        "dns_events": row.get("dns_events"),
        "tcp_events": row.get("tcp_events"),
        "icmp_events": row.get("icmp_events"),
        "low_risk_count": row.get("low_risk_count"),
        "medium_risk_count": row.get("medium_risk_count"),
        "high_risk_count": row.get("high_risk_count"),
        "blocked_devices": row.get("blocked_devices"),
        "blocked_requests": row.get("blocked_requests"),
        "avg_risk_score": _to_number(row.get("avg_risk_score")),
        "generated_at": _to_iso(row.get("generated_at")),
    }


def serialize_top_risky_device(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_ip": row.get("source_ip"),
        "event_count": row.get("event_count"),
        "avg_risk_score": _to_number(row.get("avg_risk_score")),
        "max_risk_score": _to_number(row.get("max_risk_score")),
    }
