"""Data access layer with parameterized SQL queries."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any

from backend import database as db
from backend.exceptions import ConflictError, NotFoundError

DANGEROUS_PORTS = frozenset({
    21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080,
})


def _risk_category(score: float) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

def count_devices(*, blocked_only: bool = False, trusted_only: bool = False) -> int:
    clauses = []
    params: list[Any] = []
    if blocked_only:
        clauses.append("is_blocked = TRUE")
    if trusted_only:
        clauses.append("is_trusted = TRUE")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    row = db.fetch_one(f"SELECT COUNT(*) AS total FROM devices {where}", params)
    return int(row["total"]) if row else 0


def list_devices(*, limit: int, offset: int, ip_address: str | None = None) -> list[dict]:
    params: list[Any] = []
    where_clauses = []

    if ip_address:
        where_clauses.append("d.ip_address = %s::inet")
        params.append(ip_address)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    query = f"""
        SELECT
            d.*,
            v.max_risk_score,
            v.avg_risk_score,
            v.high_risk_events
        FROM devices d
        LEFT JOIN v_device_risk_summary v ON v.device_id = d.device_id
        {where_sql}
        ORDER BY d.last_seen DESC
        LIMIT %s OFFSET %s
    """
    params.extend([limit, offset])
    return db.fetch_all(query, params)


def get_device_by_id(device_id: str) -> dict | None:
    return db.fetch_one(
        """
        SELECT d.*, v.max_risk_score, v.avg_risk_score, v.high_risk_events
        FROM devices d
        LEFT JOIN v_device_risk_summary v ON v.device_id = d.device_id
        WHERE d.device_id = %s::uuid
        """,
        (device_id,),
    )


def get_device_by_ip(ip_address: str) -> dict | None:
    return db.fetch_one(
        "SELECT * FROM devices WHERE ip_address = %s::inet",
        (ip_address,),
    )


def upsert_device_for_ip(ip_address: str) -> dict:
    return db.execute_returning(
        """
        INSERT INTO devices (ip_address, first_seen, last_seen)
        VALUES (%s::inet, NOW(), NOW())
        ON CONFLICT (ip_address) DO UPDATE
            SET last_seen = NOW(), updated_at = NOW()
        RETURNING *
        """,
        (ip_address,),
    )


def update_device_flags(
    *,
    device_id: str | None,
    ip_address: str,
    is_trusted: bool | None = None,
    is_blocked: bool | None = None,
) -> dict:
    device = None
    if device_id:
        device = get_device_by_id(device_id)
    if device is None:
        device = get_device_by_ip(ip_address)
    if device is None:
        device = upsert_device_for_ip(ip_address)
        device_id = str(device["device_id"])
    else:
        device_id = str(device["device_id"])

    sets = []
    params: list[Any] = []

    if is_trusted is not None:
        sets.append("is_trusted = %s")
        params.append(is_trusted)
    if is_blocked is not None:
        sets.append("is_blocked = %s")
        params.append(is_blocked)

    if not sets:
        return device

    # Enforce mutual exclusivity at application layer before DB check constraint.
    if is_trusted and is_blocked:
        raise ConflictError("Device cannot be both trusted and blocked.")

    params.append(device_id)
    return db.execute_returning(
        f"""
        UPDATE devices
        SET {', '.join(sets)}, updated_at = NOW()
        WHERE device_id = %s::uuid
        RETURNING *
        """,
        params,
    )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def count_events(*, protocol: str | None = None, processed: bool | None = None) -> int:
    clauses = []
    params: list[Any] = []
    if protocol:
        clauses.append("protocol = %s::protocol_type")
        params.append(protocol)
    if processed is not None:
        clauses.append("processed = %s")
        params.append(processed)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    row = db.fetch_one(f"SELECT COUNT(*) AS total FROM events {where}", params)
    return int(row["total"]) if row else 0


def list_events(
    *,
    limit: int,
    offset: int,
    protocol: str | None = None,
    source_ip: str | None = None,
) -> list[dict]:
    clauses = []
    params: list[Any] = []

    if protocol:
        clauses.append("protocol = %s::protocol_type")
        params.append(protocol)
    if source_ip:
        clauses.append("source_ip = %s::inet")
        params.append(source_ip)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])

    return db.fetch_all(
        f"""
        SELECT *
        FROM events
        {where}
        ORDER BY timestamp DESC
        LIMIT %s OFFSET %s
        """,
        params,
    )


def get_event_by_id(event_id: int) -> dict | None:
    return db.fetch_one("SELECT * FROM events WHERE event_id = %s", (event_id,))


def mark_event_processed(event_id: int) -> None:
    db.execute(
        "UPDATE events SET processed = TRUE WHERE event_id = %s",
        (event_id,),
    )


# ---------------------------------------------------------------------------
# Risk assessments
# ---------------------------------------------------------------------------

def count_risks(*, risk_category: str | None = None) -> int:
    if risk_category:
        row = db.fetch_one(
            "SELECT COUNT(*) AS total FROM risk_assessment WHERE risk_category = %s::risk_category_type",
            (risk_category,),
        )
    else:
        row = db.fetch_one("SELECT COUNT(*) AS total FROM risk_assessment")
    return int(row["total"]) if row else 0


def list_risks(
    *,
    limit: int,
    offset: int,
    risk_category: str | None = None,
    min_score: float | None = None,
) -> list[dict]:
    clauses = []
    params: list[Any] = []

    if risk_category:
        clauses.append("ra.risk_category = %s::risk_category_type")
        params.append(risk_category)
    if min_score is not None:
        clauses.append("ra.risk_score >= %s")
        params.append(min_score)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])

    return db.fetch_all(
        f"""
        SELECT
            ra.*,
            e.source_ip,
            e.destination_ip,
            e.protocol,
            e.device_id
        FROM risk_assessment ra
        JOIN events e ON e.event_id = ra.event_id
        {where}
        ORDER BY ra.assessed_at DESC
        LIMIT %s OFFSET %s
        """,
        params,
    )


def get_risk_by_event_id(event_id: int) -> dict | None:
    return db.fetch_one(
        "SELECT * FROM risk_assessment WHERE event_id = %s",
        (event_id,),
    )


def get_recent_event_stats_for_ip(source_ip: str, window_minutes: int = 15) -> dict:
    """Aggregate short-window traffic stats used by the risk engine."""
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) AS requests_in_window,
            COUNT(DISTINCT destination_ip) AS unique_destinations,
            COUNT(*) FILTER (WHERE protocol = 'DNS') AS dns_count_in_window,
            COUNT(*) FILTER (WHERE protocol = 'TCP') AS tcp_count_in_window,
            COUNT(*) FILTER (WHERE protocol = 'ICMP') AS icmp_count_in_window,
            COALESCE(AVG(packet_size), 0) AS avg_packet_size_ip
        FROM events
        WHERE source_ip = %s::inet
          AND timestamp >= NOW() - (%s || ' minutes')::interval
        """,
        (source_ip, window_minutes),
    )
    return row or {
        "requests_in_window": 0,
        "unique_destinations": 0,
        "dns_count_in_window": 0,
        "tcp_count_in_window": 0,
        "icmp_count_in_window": 0,
        "avg_packet_size_ip": 0,
    }


def compute_rule_based_risk(event: dict) -> dict[str, Any]:
    """
    Compute risk score from security rules until ML module is wired in.
    Mirrors the rule weights defined in the product spec.
    """
    source_ip = str(event["source_ip"])
    dest_port = event.get("destination_port")
    event_time: datetime = event["timestamp"]
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    stats = get_recent_event_stats_for_ip(source_ip)
    adjustments: list[dict[str, Any]] = []

    base_score = 20.0
    anomaly_score = -0.15

    if dest_port in DANGEROUS_PORTS:
        adjustments.append({"rule": "dangerous_port", "delta": 15})
    if stats["requests_in_window"] >= 100:
        adjustments.append({"rule": "high_request_volume", "delta": 18})
    if stats["unique_destinations"] >= 25:
        adjustments.append({"rule": "scanning_behaviour", "delta": 12})
    if event_time.hour < 6 or event_time.hour >= 22:
        adjustments.append({"rule": "night_activity", "delta": 7})

    packet_size = float(event.get("packet_size") or 0)
    avg_size = float(stats.get("avg_packet_size_ip") or packet_size or 1)
    if avg_size > 0:
        deviation = abs(packet_size - avg_size) / avg_size
        if deviation >= 2.5:
            adjustments.append({"rule": "extreme_deviation", "delta": 20})

    rule_delta = sum(item["delta"] for item in adjustments)
    final_score = min(100.0, base_score + rule_delta)
    category = _risk_category(final_score)

    explanation = _build_rule_explanation(event, adjustments, final_score, stats)

    return {
        "risk_score": round(final_score, 2),
        "risk_category": category,
        "anomaly_score": anomaly_score,
        "ml_score": None,
        "rule_adjustments": adjustments,
        "explanation": explanation,
    }


def _build_rule_explanation(
    event: dict,
    adjustments: list[dict],
    score: float,
    stats: dict,
) -> dict[str, str]:
    protocol = event.get("protocol", "UNKNOWN")
    source = str(event.get("source_ip"))
    destination = str(event.get("destination_ip"))

    triggered = ", ".join(a["rule"].replace("_", " ") for a in adjustments) or "baseline traffic profile"
    observation = (
        f"{protocol} traffic from {source} to {destination} "
        f"with {stats['requests_in_window']} requests in the last 15 minutes."
    )
    context = (
        f"Rule engine applied {len(adjustments)} adjustment(s): {triggered}. "
        f"Computed risk score is {score:.1f}."
    )
    if score >= 61:
        recommendation = "Investigate immediately and consider blocking the source device."
    elif score >= 31:
        recommendation = "Monitor closely and validate whether this behaviour is expected."
    else:
        recommendation = "No immediate action required; continue passive monitoring."

    return {
        "observation": observation,
        "context": context,
        "recommendation": recommendation,
    }


def create_risk_assessment(event_id: int, assessment: dict[str, Any]) -> dict:
    return db.execute_returning(
        """
        INSERT INTO risk_assessment (
            event_id, risk_score, risk_category, explanation,
            anomaly_score, ml_score, rule_adjustments
        )
        VALUES (%s, %s, %s::risk_category_type, %s::jsonb, %s, %s, %s::jsonb)
        RETURNING *
        """,
        (
            event_id,
            assessment["risk_score"],
            assessment["risk_category"],
            json.dumps(assessment["explanation"]),
            assessment["anomaly_score"],
            assessment.get("ml_score"),
            json.dumps(assessment["rule_adjustments"]),
        ),
    )


# ---------------------------------------------------------------------------
# User decisions
# ---------------------------------------------------------------------------

def count_decisions(*, active_only: bool = True) -> int:
    if active_only:
        row = db.fetch_one(
            "SELECT COUNT(*) AS total FROM user_decisions WHERE is_active = TRUE"
        )
    else:
        row = db.fetch_one("SELECT COUNT(*) AS total FROM user_decisions")
    return int(row["total"]) if row else 0


def list_decisions(*, limit: int, offset: int, active_only: bool = True) -> list[dict]:
    where = "WHERE is_active = TRUE" if active_only else ""
    return db.fetch_all(
        f"""
        SELECT *
        FROM user_decisions
        {where}
        ORDER BY decided_at DESC
        LIMIT %s OFFSET %s
        """,
        (limit, offset),
    )


def deactivate_decisions_for_ip(ip_address: str) -> None:
    db.execute(
        """
        UPDATE user_decisions
        SET is_active = FALSE
        WHERE ip_address = %s::inet AND is_active = TRUE
        """,
        (ip_address,),
    )


def create_decision(
    *,
    ip_address: str,
    action: str,
    device_id: str | None = None,
    reason: str | None = None,
    assessment_id: int | None = None,
    triggered_by: str = "api",
) -> dict:
    return db.execute_returning(
        """
        INSERT INTO user_decisions (
            device_id, ip_address, action, reason, assessment_id, triggered_by
        )
        VALUES (%s::uuid, %s::inet, %s::decision_action_type, %s, %s, %s)
        RETURNING *
        """,
        (device_id, ip_address, action, reason, assessment_id, triggered_by),
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def get_latest_daily_summary() -> dict | None:
    return db.fetch_one(
        """
        SELECT *
        FROM daily_summary
        ORDER BY summary_date DESC
        LIMIT 1
        """
    )


def get_live_stats() -> dict[str, Any]:
    devices = db.fetch_one(
        """
        SELECT
            COUNT(*) AS total_devices,
            COUNT(*) FILTER (WHERE is_blocked = TRUE) AS blocked_devices,
            COUNT(*) FILTER (WHERE is_trusted = TRUE) AS trusted_devices
        FROM devices
        """
    )
    events = db.fetch_one(
        """
        SELECT
            COUNT(*) AS total_events,
            COUNT(*) FILTER (WHERE protocol = 'DNS') AS dns_events,
            COUNT(*) FILTER (WHERE protocol = 'TCP') AS tcp_events,
            COUNT(*) FILTER (WHERE protocol = 'ICMP') AS icmp_events
        FROM events
        """
    )
    risks = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE risk_category = 'Low') AS low_risk_count,
            COUNT(*) FILTER (WHERE risk_category = 'Medium') AS medium_risk_count,
            COUNT(*) FILTER (WHERE risk_category = 'High') AS high_risk_count,
            COALESCE(AVG(risk_score), 0) AS avg_risk_score
        FROM risk_assessment
        """
    )
    hourly = db.fetch_all(
        """
        SELECT
            EXTRACT(HOUR FROM timestamp)::int AS hour,
            COUNT(*) AS count
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1
        """
    )
    protocol_dist = db.fetch_all(
        """
        SELECT protocol::text AS protocol, COUNT(*) AS count
        FROM events
        GROUP BY protocol
        """
    )

    return {
        "devices": devices or {},
        "events": events or {},
        "risks": risks or {},
        "hourly_distribution": {str(r["hour"]): r["count"] for r in hourly},
        "protocol_distribution": {r["protocol"]: r["count"] for r in protocol_dist},
    }


def build_stats_payload() -> dict[str, Any]:
    summary = get_latest_daily_summary()
    live = get_live_stats()

    if summary:
        payload = dict(summary)
        payload["live"] = live
        return payload

    return {
        "summary_date": date.today().isoformat(),
        "total_devices": live["devices"].get("total_devices", 0),
        "active_devices": live["devices"].get("total_devices", 0),
        "total_events": live["events"].get("total_events", 0),
        "dns_events": live["events"].get("dns_events", 0),
        "tcp_events": live["events"].get("tcp_events", 0),
        "icmp_events": live["events"].get("icmp_events", 0),
        "low_risk_count": live["risks"].get("low_risk_count", 0),
        "medium_risk_count": live["risks"].get("medium_risk_count", 0),
        "high_risk_count": live["risks"].get("high_risk_count", 0),
        "blocked_devices": live["devices"].get("blocked_devices", 0),
        "blocked_requests": 0,
        "suspicious_devices": 0,
        "avg_risk_score": live["risks"].get("avg_risk_score", 0),
        "peak_hour": None,
        "top_risky_ips": [],
        "hourly_distribution": live.get("hourly_distribution", {}),
        "protocol_distribution": live.get("protocol_distribution", {}),
        "live": live,
    }


def get_summary_for_date(summary_date: str) -> dict | None:
    return db.fetch_one(
        "SELECT * FROM daily_summary WHERE summary_date = %s::date",
        (summary_date,),
    )


def require_device(device_id: str | None, ip_address: str) -> dict:
    device = get_device_by_id(device_id) if device_id else get_device_by_ip(ip_address)
    if device is None:
        device = upsert_device_for_ip(ip_address)
    return device


def require_event(event_id: int) -> dict:
    event = get_event_by_id(event_id)
    if event is None:
        raise NotFoundError(f"Event {event_id} not found.")
    return event


# ---------------------------------------------------------------------------
# Dashboard/report support (Appendix A endpoints)
# ---------------------------------------------------------------------------

def get_device_stats() -> dict[str, Any]:
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) AS total_devices,
            COUNT(*) FILTER (WHERE is_trusted = TRUE) AS trusted_devices,
            COUNT(*) FILTER (WHERE is_blocked = TRUE) AS blocked_devices,
            COUNT(*) FILTER (WHERE first_seen >= CURRENT_DATE) AS new_today
        FROM devices
        """
    )
    return row or {"total_devices": 0, "trusted_devices": 0, "blocked_devices": 0, "new_today": 0}


def get_events_by_protocol() -> list[dict]:
    return db.fetch_all(
        """
        SELECT protocol::text AS protocol, COUNT(*) AS count
        FROM events
        GROUP BY protocol
        ORDER BY count DESC
        """
    )


def get_events_hourly_today() -> list[dict]:
    return db.fetch_all(
        """
        SELECT EXTRACT(HOUR FROM timestamp)::int AS hour, COUNT(*) AS count
        FROM events
        WHERE timestamp >= CURRENT_DATE
        GROUP BY 1
        ORDER BY 1
        """
    )


def get_top_risky_devices(limit: int = 10) -> list[dict]:
    return db.fetch_all(
        """
        SELECT
            e.source_ip::text AS source_ip,
            COUNT(*) AS event_count,
            ROUND(AVG(ra.risk_score), 2) AS avg_risk_score,
            MAX(ra.risk_score) AS max_risk_score
        FROM risk_assessment ra
        JOIN events e ON e.event_id = ra.event_id
        GROUP BY e.source_ip
        ORDER BY avg_risk_score DESC
        LIMIT %s
        """,
        (limit,),
    )


def get_risk_summary() -> dict[str, Any]:
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE risk_category = 'Low') AS low,
            COUNT(*) FILTER (WHERE risk_category = 'Medium') AS medium,
            COUNT(*) FILTER (WHERE risk_category = 'High') AS high,
            COALESCE(ROUND(AVG(risk_score), 2), 0) AS avg_score
        FROM risk_assessment
        """
    )
    summary = row or {"low": 0, "medium": 0, "high": 0, "avg_score": 0}
    return {
        "summary": summary,
        "top_risky_devices": get_top_risky_devices(limit=10),
    }


def get_active_decision_for_ip(ip_address: str) -> dict | None:
    return db.fetch_one(
        """
        SELECT * FROM user_decisions
        WHERE ip_address = %s::inet AND is_active = TRUE
        ORDER BY decided_at DESC
        LIMIT 1
        """,
        (ip_address,),
    )


def get_decision_history(*, ip_address: str | None, limit: int) -> list[dict]:
    if ip_address:
        return db.fetch_all(
            """
            SELECT * FROM user_decisions
            WHERE ip_address = %s::inet
            ORDER BY decided_at DESC
            LIMIT %s
            """,
            (ip_address, limit),
        )
    return db.fetch_all(
        "SELECT * FROM user_decisions ORDER BY decided_at DESC LIMIT %s",
        (limit,),
    )


def get_decision_summary() -> dict[str, int]:
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE action = 'allow' AND is_active) AS allow_count,
            COUNT(*) FILTER (WHERE action = 'block' AND is_active) AS block_count,
            COUNT(*) FILTER (WHERE action = 'always_allow' AND is_active) AS always_allow_count,
            COUNT(*) FILTER (WHERE action = 'always_block' AND is_active) AS always_block_count,
            COUNT(*) FILTER (WHERE is_active) AS active_count,
            COUNT(*) AS total
        FROM user_decisions
        """
    )
    return row or {
        "allow_count": 0, "block_count": 0, "always_allow_count": 0,
        "always_block_count": 0, "active_count": 0, "total": 0,
    }


def is_ip_blocked(ip_address: str) -> bool:
    device = get_device_by_ip(ip_address)
    return bool(device and device.get("is_blocked"))


def list_daily_summaries(days: int = 7) -> list[dict]:
    return db.fetch_all(
        """
        SELECT * FROM daily_summary
        ORDER BY summary_date DESC
        LIMIT %s
        """,
        (days,),
    )


def generate_daily_summary(summary_date: str | None = None) -> dict:
    """Recompute and upsert the daily_summary row for the given date (default: today)."""
    target_date = summary_date or date.today().isoformat()

    events_row = db.fetch_one(
        """
        SELECT
            COUNT(*) AS total_events,
            COUNT(*) FILTER (WHERE protocol = 'DNS') AS dns_events,
            COUNT(*) FILTER (WHERE protocol = 'TCP') AS tcp_events,
            COUNT(*) FILTER (WHERE protocol = 'ICMP') AS icmp_events,
            COUNT(DISTINCT source_ip) AS unique_devices
        FROM events
        WHERE timestamp::date = %s::date
        """,
        (target_date,),
    ) or {}

    risk_row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE ra.risk_category = 'Low') AS low_risk_count,
            COUNT(*) FILTER (WHERE ra.risk_category = 'Medium') AS medium_risk_count,
            COUNT(*) FILTER (WHERE ra.risk_category = 'High') AS high_risk_count,
            COALESCE(AVG(ra.risk_score), 0) AS avg_risk_score
        FROM risk_assessment ra
        JOIN events e ON e.event_id = ra.event_id
        WHERE e.timestamp::date = %s::date
        """,
        (target_date,),
    ) or {}

    blocked_requests_row = db.fetch_one(
        """
        SELECT COUNT(*) AS blocked_requests
        FROM user_decisions
        WHERE action IN ('block', 'always_block') AND decided_at::date = %s::date
        """,
        (target_date,),
    ) or {}

    devices_row = db.fetch_one("SELECT COUNT(*) AS total_devices FROM devices") or {}
    blocked_devices_row = db.fetch_one(
        "SELECT COUNT(*) AS blocked_devices FROM devices WHERE is_blocked = TRUE"
    ) or {}

    return db.execute_returning(
        """
        INSERT INTO daily_summary (
            summary_date, total_devices, active_devices, unique_devices, total_events,
            dns_events, tcp_events, icmp_events,
            low_risk_count, medium_risk_count, high_risk_count,
            blocked_devices, blocked_requests, avg_risk_score
        )
        VALUES (%s::date, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (summary_date) DO UPDATE SET
            total_devices = EXCLUDED.total_devices,
            active_devices = EXCLUDED.active_devices,
            unique_devices = EXCLUDED.unique_devices,
            total_events = EXCLUDED.total_events,
            dns_events = EXCLUDED.dns_events,
            tcp_events = EXCLUDED.tcp_events,
            icmp_events = EXCLUDED.icmp_events,
            low_risk_count = EXCLUDED.low_risk_count,
            medium_risk_count = EXCLUDED.medium_risk_count,
            high_risk_count = EXCLUDED.high_risk_count,
            blocked_devices = EXCLUDED.blocked_devices,
            blocked_requests = EXCLUDED.blocked_requests,
            avg_risk_score = EXCLUDED.avg_risk_score
        RETURNING *
        """,
        (
            target_date,
            devices_row.get("total_devices", 0) or 0,
            devices_row.get("total_devices", 0) or 0,
            events_row.get("unique_devices", 0) or 0,
            events_row.get("total_events", 0) or 0,
            events_row.get("dns_events", 0) or 0,
            events_row.get("tcp_events", 0) or 0,
            events_row.get("icmp_events", 0) or 0,
            risk_row.get("low_risk_count", 0) or 0,
            risk_row.get("medium_risk_count", 0) or 0,
            risk_row.get("high_risk_count", 0) or 0,
            blocked_devices_row.get("blocked_devices", 0) or 0,
            blocked_requests_row.get("blocked_requests", 0) or 0,
            float(risk_row.get("avg_risk_score", 0) or 0),
        ),
    )
