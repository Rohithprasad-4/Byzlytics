"""Stage 3 — Clean and normalise data types ahead of feature transformation."""

from __future__ import annotations

import pandas as pd


def clean_events(df: pd.DataFrame) -> pd.DataFrame:
    """Normalise dtypes: protocol upper-case, ports/sizes numeric, timestamps to UTC."""
    if df.empty:
        return df

    df = df.copy()

    df["protocol"] = df["protocol"].astype(str).str.upper()
    df["source_ip"] = df["source_ip"].astype(str)
    df["destination_ip"] = df["destination_ip"].astype(str)

    df["source_port"] = pd.to_numeric(df.get("source_port"), errors="coerce").fillna(0).astype(int)
    df["destination_port"] = (
        pd.to_numeric(df.get("destination_port"), errors="coerce").fillna(0).astype(int)
    )
    df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(0.0).astype(float)

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)

    # Deduplicate exact repeats (same source/destination/port/protocol within the same second).
    df = df.drop_duplicates(
        subset=["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "timestamp"]
    ).reset_index(drop=True)

    return df
