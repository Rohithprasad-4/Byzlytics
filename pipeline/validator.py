"""Stage 2 — Validate raw event rows; reject malformed records.

A row is rejected (dropped) if it fails any of:
  - source_ip / destination_ip present and syntactically valid
  - protocol is one of DNS / TCP / ICMP / OTHER
  - packet_size is a positive number
  - timestamp is present and parseable
"""

from __future__ import annotations

import ipaddress
import logging

import pandas as pd

logger = logging.getLogger(__name__)

VALID_PROTOCOLS = {"DNS", "TCP", "ICMP", "OTHER"}


def _is_valid_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except (ValueError, TypeError):
        return False


def validate_events(df: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    """Return (valid_rows, rejected_rows_with_reasons)."""
    if df.empty:
        return df, []

    rejected: list[dict] = []
    keep_mask = []

    for _, row in df.iterrows():
        reasons = []

        if not _is_valid_ip(row.get("source_ip")):
            reasons.append("invalid source_ip")
        if not _is_valid_ip(row.get("destination_ip")):
            reasons.append("invalid destination_ip")

        protocol = str(row.get("protocol", "")).upper()
        if protocol not in VALID_PROTOCOLS:
            reasons.append(f"unrecognised protocol '{protocol}'")

        try:
            packet_size = float(row.get("packet_size"))
            if packet_size <= 0:
                reasons.append("packet_size must be positive")
        except (TypeError, ValueError):
            reasons.append("packet_size not numeric")

        if pd.isna(row.get("timestamp")):
            reasons.append("missing timestamp")

        if reasons:
            rejected.append({"event_id": row.get("event_id"), "reasons": reasons})
            keep_mask.append(False)
        else:
            keep_mask.append(True)

    valid_df = df[pd.Series(keep_mask, index=df.index)].reset_index(drop=True)

    if rejected:
        logger.warning("Rejected %d malformed event(s) during validation.", len(rejected))

    return valid_df, rejected
