"""Stage 1 — Collect unprocessed events from PostgreSQL into a DataFrame."""

from __future__ import annotations

import pandas as pd

from backend import database as db


def collect_unprocessed_events(limit: int = 500) -> pd.DataFrame:
    """Fetch events not yet scored by the ML/AI pipeline (processed = FALSE)."""
    rows = db.fetch_all(
        """
        SELECT event_id, device_id, timestamp, protocol, source_ip,
               destination_ip, source_port, destination_port, packet_size,
               capture_iface, raw_metadata
        FROM events
        WHERE processed = FALSE
        ORDER BY timestamp ASC
        LIMIT %s
        """,
        (limit,),
    )
    return pd.DataFrame(rows)


def collect_events_by_ids(event_ids: list[int]) -> pd.DataFrame:
    if not event_ids:
        return pd.DataFrame()
    rows = db.fetch_all(
        """
        SELECT event_id, device_id, timestamp, protocol, source_ip,
               destination_ip, source_port, destination_port, packet_size,
               capture_iface, raw_metadata
        FROM events
        WHERE event_id = ANY(%s)
        ORDER BY timestamp ASC
        """,
        (event_ids,),
    )
    return pd.DataFrame(rows)
