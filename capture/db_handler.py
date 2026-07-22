"""Persist parsed capture events to PostgreSQL and maintain the devices table.

Also enforces the block-list: capture.py calls is_ip_permitted() before
saving a packet so that devices the user has blocked (or always_blocked)
stop generating new events, per PO-01/PO-07 in the project report.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from backend import database as db

logger = logging.getLogger(__name__)


def is_ip_permitted(ip_address: str) -> bool:
    """Return False if the IP currently has an active block/always_block decision."""
    row = db.fetch_one(
        """
        SELECT action FROM user_decisions
        WHERE ip_address = %s::inet AND is_active = TRUE
        ORDER BY decided_at DESC
        LIMIT 1
        """,
        (ip_address,),
    )
    if row is None:
        return True
    return row["action"] not in ("block", "always_block")


def upsert_device(ip_address: str, mac_address: str | None = None) -> dict:
    return db.execute_returning(
        """
        INSERT INTO devices (ip_address, mac_address, first_seen, last_seen)
        VALUES (%s::inet, %s::macaddr, NOW(), NOW())
        ON CONFLICT (ip_address) DO UPDATE
            SET last_seen = NOW(),
                mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                updated_at = NOW()
        RETURNING *
        """,
        (ip_address, mac_address),
    )


def save_event(event: dict[str, Any], *, capture_iface: str | None = None) -> dict | None:
    """Persist a parsed event; skip and return None if the source IP is blocked."""
    if not is_ip_permitted(event["source_ip"]):
        logger.debug("Dropping event from blocked IP %s", event["source_ip"])
        return None

    device = upsert_device(event["source_ip"])

    row = db.execute_returning(
        """
        INSERT INTO events (
            device_id, timestamp, protocol, source_ip, destination_ip,
            source_port, destination_port, packet_size, capture_iface, raw_metadata
        )
        VALUES (%s::uuid, %s, %s::protocol_type, %s::inet, %s::inet, %s, %s, %s, %s, %s::jsonb)
        RETURNING *
        """,
        (
            device["device_id"],
            event["timestamp"],
            event["protocol"],
            event["source_ip"],
            event["destination_ip"],
            event.get("source_port"),
            event.get("destination_port"),
            event["packet_size"],
            capture_iface,
            json.dumps(event.get("raw_metadata", {})),
        ),
    )
    return row


def save_events_batch(events: list[dict[str, Any]], *, capture_iface: str | None = None) -> int:
    saved = 0
    for event in events:
        try:
            if save_event(event, capture_iface=capture_iface) is not None:
                saved += 1
        except Exception:  # pragma: no cover - defensive; capture must not crash
            logger.exception("Failed to save captured event: %s", event)
    return saved
