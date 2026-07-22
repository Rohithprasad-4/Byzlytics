"""Phase 11 — Data collectors for the daily security PDF report.

Seven sections, each backed by a dedicated query function:
  1. Executive Summary        4. Blocked Requests
  2. Traffic Overview         5. Historical Trend
  3. Risk Analysis            6. Hourly Breakdown
                              7. Conclusion (derived, not queried)
"""

from __future__ import annotations

from datetime import date
from typing import Any

from backend import database as db, models


def _target_date(report_date: str | None) -> str:
    return report_date or date.today().isoformat()


def collect_executive_summary(report_date: str | None = None) -> dict[str, Any]:
    target = _target_date(report_date)
    summary = models.get_summary_for_date(target)
    if summary:
        return dict(summary)

    generated = models.generate_daily_summary(target)
    return dict(generated) if generated else {"summary_date": target}


def collect_traffic_overview(report_date: str | None = None) -> dict[str, Any]:
    target = _target_date(report_date)
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE protocol = 'DNS') AS dns_events,
            COUNT(*) FILTER (WHERE protocol = 'TCP') AS tcp_events,
            COUNT(*) FILTER (WHERE protocol = 'ICMP') AS icmp_events,
            COUNT(*) AS total_events
        FROM events
        WHERE timestamp::date = %s::date
        """,
        (target,),
    )
    return row or {"dns_events": 0, "tcp_events": 0, "icmp_events": 0, "total_events": 0}


def collect_risk_analysis(report_date: str | None = None) -> dict[str, Any]:
    target = _target_date(report_date)
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE ra.risk_category = 'Low') AS low_count,
            COUNT(*) FILTER (WHERE ra.risk_category = 'Medium') AS medium_count,
            COUNT(*) FILTER (WHERE ra.risk_category = 'High') AS high_count,
            COALESCE(AVG(ra.risk_score), 0) AS avg_score,
            COALESCE(MAX(ra.risk_score), 0) AS max_score,
            COUNT(*) AS total
        FROM risk_assessment ra
        JOIN events e ON e.event_id = ra.event_id
        WHERE e.timestamp::date = %s::date
        """,
        (target,),
    ) or {}

    top_devices = db.fetch_all(
        """
        SELECT
            e.source_ip::text AS source_ip,
            ROUND(AVG(ra.risk_score), 2) AS avg_risk_score,
            COUNT(*) AS event_count,
            (ARRAY_AGG(ra.explanation ORDER BY ra.risk_score DESC))[1] AS top_explanation
        FROM risk_assessment ra
        JOIN events e ON e.event_id = ra.event_id
        WHERE e.timestamp::date = %s::date
        GROUP BY e.source_ip
        ORDER BY avg_risk_score DESC
        LIMIT 10
        """,
        (target,),
    )

    return {"counts": row, "top_suspicious_devices": top_devices}


def collect_blocked_requests(report_date: str | None = None) -> list[dict]:
    target = _target_date(report_date)
    return db.fetch_all(
        """
        SELECT
            ud.ip_address::text AS ip_address,
            d.device_type::text AS device_type,
            ud.action::text AS action,
            ud.reason,
            ud.decided_at
        FROM user_decisions ud
        LEFT JOIN devices d ON d.device_id = ud.device_id
        WHERE ud.action IN ('block', 'always_block') AND ud.decided_at::date = %s::date
        ORDER BY ud.decided_at DESC
        """,
        (target,),
    )


def collect_historical_trend(report_date: str | None = None, days: int = 7) -> list[dict]:
    return models.list_daily_summaries(days=days)


def collect_hourly_breakdown(report_date: str | None = None) -> list[dict]:
    target = _target_date(report_date)
    return db.fetch_all(
        """
        SELECT
            EXTRACT(HOUR FROM timestamp)::int AS hour,
            COUNT(*) FILTER (WHERE protocol = 'DNS') AS dns_count,
            COUNT(*) FILTER (WHERE protocol = 'TCP') AS tcp_count,
            COUNT(*) FILTER (WHERE protocol = 'ICMP') AS icmp_count,
            COUNT(*) AS total
        FROM events
        WHERE timestamp::date = %s::date
        GROUP BY 1
        ORDER BY 1
        """,
        (target,),
    )


def build_conclusion(risk_analysis: dict[str, Any]) -> str:
    counts = risk_analysis.get("counts", {})
    high_count = int(counts.get("high_count") or 0)
    avg_score = float(counts.get("avg_score") or 0)

    if high_count >= 5 or avg_score >= 61:
        level = "HIGH"
        narrative = (
            "Multiple high-risk events were detected today. Immediate review of the flagged "
            "devices is recommended, and any device exhibiting repeated high-risk activity "
            "should be blocked pending investigation."
        )
    elif high_count >= 1 or avg_score >= 31:
        level = "MODERATE"
        narrative = (
            "Some elevated-risk activity was observed today. No devices require immediate "
            "action, but continued monitoring of flagged IPs is advised."
        )
    else:
        level = "LOW"
        narrative = (
            "Network activity today was consistent with normal baseline behaviour. "
            "No significant threats were identified."
        )

    return f"Overall threat level: {level}. {narrative}"


def build_report_context(report_date: str | None = None) -> dict[str, Any]:
    """Collect all seven report sections into a single context dict."""
    target = _target_date(report_date)
    risk_analysis = collect_risk_analysis(target)

    return {
        "report_date": target,
        "executive_summary": collect_executive_summary(target),
        "traffic_overview": collect_traffic_overview(target),
        "risk_analysis": risk_analysis,
        "blocked_requests": collect_blocked_requests(target),
        "historical_trend": collect_historical_trend(target),
        "hourly_breakdown": collect_hourly_breakdown(target),
        "conclusion": build_conclusion(risk_analysis),
    }
