"""Stage 4 — Transform cleaned rows into intrinsic numerical features.

Produces the columns that can be derived from a single event row alone
(no database lookups required). The enrichment stage adds the
remaining historical/contextual columns to complete the 21-column
feature matrix defined in ml.features.FEATURE_COLUMNS.
"""

from __future__ import annotations

import pandas as pd

from ml.features import DANGEROUS_PORTS


def transform_events(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    df = df.copy()

    df["protocol_dns"] = (df["protocol"] == "DNS").astype(int)
    df["protocol_tcp"] = (df["protocol"] == "TCP").astype(int)
    df["protocol_icmp"] = (df["protocol"] == "ICMP").astype(int)

    df["is_dangerous_port"] = df["destination_port"].isin(DANGEROUS_PORTS).astype(int)

    ts = pd.to_datetime(df["timestamp"], utc=True)
    df["hour_of_day"] = ts.dt.hour
    df["day_of_week"] = ts.dt.dayofweek
    df["is_night"] = ((df["hour_of_day"] < 6) | (df["hour_of_day"] >= 22)).astype(int)
    df["is_business_hours"] = ((df["hour_of_day"] >= 9) & (df["hour_of_day"] <= 18)).astype(int)

    return df
