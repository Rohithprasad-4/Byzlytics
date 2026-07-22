"""Stage 5 — Enrich rows with historical per-IP context from PostgreSQL.

Completes the 21-column feature matrix by adding rate/behaviour
statistics computed from the events table (requests in the last
15/60 minutes, unique destinations contacted, historical average
packet size and request rate, and device trust/novelty flags).
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from backend import database as db


def _historical_stats_for_ip(source_ip: str, as_of) -> dict[str, Any]:
    row = db.fetch_one(
        """
        SELECT
            COUNT(*) FILTER (WHERE timestamp >= %(as_of)s - INTERVAL '15 minutes') AS requests_15,
            COUNT(*) FILTER (WHERE timestamp >= %(as_of)s - INTERVAL '60 minutes') AS requests_60,
            COUNT(DISTINCT destination_ip) FILTER (
                WHERE timestamp >= %(as_of)s - INTERVAL '15 minutes'
            ) AS unique_dest_15,
            COUNT(DISTINCT destination_ip) FILTER (
                WHERE timestamp >= %(as_of)s - INTERVAL '60 minutes'
            ) AS unique_dest_60,
            COALESCE(AVG(packet_size), 0) AS avg_packet_size,
            COALESCE(
                AVG(packet_size) FILTER (WHERE timestamp >= %(as_of)s - INTERVAL '24 hours'),
                0
            ) AS avg_packet_size_24h,
            COUNT(*) FILTER (
                WHERE timestamp >= %(as_of)s - INTERVAL '24 hours'
            ) / 24.0 AS historical_avg_per_hour
        FROM events
        WHERE source_ip = %(ip)s::inet AND timestamp < %(as_of)s
        """,
        {"ip": source_ip, "as_of": as_of},
    )
    return row or {}


def _device_flags_for_ip(source_ip: str, as_of) -> dict[str, Any]:
    row = db.fetch_one(
        "SELECT is_trusted, first_seen FROM devices WHERE ip_address = %s::inet",
        (source_ip,),
    )
    if row is None:
        return {"is_known_device": 0, "is_new_device": 1}

    is_new = 0
    if row.get("first_seen") is not None:
        try:
            delta = as_of - row["first_seen"]
            is_new = int(delta.total_seconds() <= 3600)
        except TypeError:
            is_new = 0

    return {
        "is_known_device": int(bool(row.get("is_trusted"))),
        "is_new_device": is_new,
    }


def enrich_events(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    df = df.copy()
    enriched_rows = []

    for _, row in df.iterrows():
        source_ip = row["source_ip"]
        as_of = row["timestamp"]

        hist = _historical_stats_for_ip(source_ip, as_of)
        flags = _device_flags_for_ip(source_ip, as_of)

        requests_60 = float(hist.get("requests_60") or 0)
        historical_avg = float(hist.get("historical_avg_per_hour") or 0)
        avg_packet_size_ip = float(hist.get("avg_packet_size") or row["packet_size"] or 1)

        deviation_score = (
            abs(row["packet_size"] - avg_packet_size_ip) / avg_packet_size_ip
            if avg_packet_size_ip > 0
            else 0.0
        )
        request_rate_ratio = requests_60 / historical_avg if historical_avg > 0 else 1.0

        enriched_rows.append({
            "requests_last_15min": float(hist.get("requests_15") or 0),
            "requests_last_60min": requests_60,
            "unique_destinations_15min": float(hist.get("unique_dest_15") or 0),
            "unique_destinations_60min": float(hist.get("unique_dest_60") or 0),
            "avg_packet_size_ip": round(avg_packet_size_ip, 2),
            "deviation_score": round(deviation_score, 4),
            "historical_avg_requests_per_hour": round(historical_avg, 2),
            "request_rate_ratio": round(request_rate_ratio, 3),
            "is_known_device": flags["is_known_device"],
            "is_new_device": flags["is_new_device"],
        })

    enriched_df = pd.DataFrame(enriched_rows, index=df.index)
    return pd.concat([df, enriched_df], axis=1)
