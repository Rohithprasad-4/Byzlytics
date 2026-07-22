"""Data-engineering pipeline orchestrator (Phase 5).

Runs: Collect -> Validate -> Clean -> Transform -> Enrich, producing a
DataFrame whose columns exactly match ml.features.FEATURE_COLUMNS
(plus identifying columns event_id, source_ip, destination_ip,
protocol, timestamp, device_id kept for downstream use).

Usage:
    from pipeline.pipeline import run_pipeline
    df, rejected = run_pipeline(limit=500)
"""

from __future__ import annotations

import logging

import pandas as pd

from ml.features import FEATURE_COLUMNS
from pipeline.cleaner import clean_events
from pipeline.collector import collect_events_by_ids, collect_unprocessed_events
from pipeline.enricher import enrich_events
from pipeline.transformer import transform_events
from pipeline.validator import validate_events

logger = logging.getLogger(__name__)

IDENTIFIER_COLUMNS = [
    "event_id", "device_id", "timestamp", "protocol", "source_ip", "destination_ip",
]


def _finalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=IDENTIFIER_COLUMNS + FEATURE_COLUMNS)
    keep = [c for c in IDENTIFIER_COLUMNS if c in df.columns] + FEATURE_COLUMNS
    return df[keep]


def run_pipeline(*, limit: int = 500, event_ids: list[int] | None = None) -> tuple[pd.DataFrame, list[dict]]:
    """Run the full 5-stage pipeline. Returns (feature_df, rejected_rows)."""
    logger.info("Pipeline stage 1/5: collect")
    raw_df = (
        collect_events_by_ids(event_ids) if event_ids else collect_unprocessed_events(limit)
    )
    if raw_df.empty:
        logger.info("No events to process.")
        return _finalise_columns(raw_df), []

    logger.info("Pipeline stage 2/5: validate (%d rows in)", len(raw_df))
    valid_df, rejected = validate_events(raw_df)

    logger.info("Pipeline stage 3/5: clean (%d rows valid)", len(valid_df))
    clean_df = clean_events(valid_df)

    logger.info("Pipeline stage 4/5: transform")
    transformed_df = transform_events(clean_df)

    logger.info("Pipeline stage 5/5: enrich")
    enriched_df = enrich_events(transformed_df)

    result = _finalise_columns(enriched_df)
    logger.info("Pipeline complete: %d rows produced, %d rejected", len(result), len(rejected))
    return result, rejected


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from backend.config import load_config
    from backend.database import init_db_pool

    init_db_pool(load_config().database)
    features_df, rejected_rows = run_pipeline()
    print(features_df.head())
    print(f"Rows: {len(features_df)}, Rejected: {len(rejected_rows)}")
