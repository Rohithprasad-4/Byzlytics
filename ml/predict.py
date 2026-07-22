"""Phase 6 — Load persisted model/scaler and score feature vectors.

Risk mapping is calibrated per-model: ml.training saves the 1st/99th
percentile of score_samples() observed on the training set to
models/score_range.json, and we linearly map that empirical range to
0-100 (higher score_samples = more normal = lower risk). This is more
reliable than assuming the theoretical [-0.5, +0.5] range from the
IsolationForest docs, which real trained models rarely span exactly.
If score_range.json is missing (e.g. an older model artifact), we fall
back to the documented static formula:

    risk_score = (0.5 - raw_anomaly_score) * 100   clipped to [0, 100]
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ml.features import FEATURE_COLUMNS

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_FILE = MODELS_DIR / "model.pkl"
SCALER_FILE = MODELS_DIR / "scaler.pkl"
SCORE_RANGE_FILE = MODELS_DIR / "score_range.json"


class ModelNotTrainedError(RuntimeError):
    """Raised when model.pkl / scaler.pkl are missing."""


@functools.lru_cache(maxsize=1)
def _load_artifacts() -> tuple[Any, Any]:
    if not MODEL_FILE.exists() or not SCALER_FILE.exists():
        raise ModelNotTrainedError(
            "Model artifacts not found. Run `python -m ml.generate_dataset` "
            "then `python -m ml.training` before scoring events."
        )
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    return model, scaler


@functools.lru_cache(maxsize=1)
def _load_score_range() -> tuple[float, float] | None:
    if not SCORE_RANGE_FILE.exists():
        return None
    data = json.loads(SCORE_RANGE_FILE.read_text())
    return float(data["score_min"]), float(data["score_max"])


def clear_cache() -> None:
    """Force the next call to reload model.pkl/scaler.pkl from disk (e.g. after retraining)."""
    _load_artifacts.cache_clear()
    _load_score_range.cache_clear()


def map_to_risk_scale(raw_anomaly_score: float) -> float:
    """Map IsolationForest's score_samples() output to a 0-100 risk scale."""
    calibration = _load_score_range()
    if calibration is not None:
        score_min, score_max = calibration
        span = score_max - score_min
        if span <= 0:
            return 50.0
        # Higher raw score = more normal => lower risk; invert the fraction.
        fraction = (score_max - raw_anomaly_score) / span
        return float(np.clip(fraction * 100, 0, 100))

    risk_score = (0.5 - raw_anomaly_score) * 100
    return float(np.clip(risk_score, 0, 100))


def risk_category(score: float) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


def score_feature_row(features: dict[str, float]) -> dict[str, Any]:
    """Score a single feature dict (keys = ml.features.FEATURE_COLUMNS).

    Returns raw_anomaly_score, base risk_score (0-100, before rule bonuses),
    and the preliminary risk_category.
    """
    model, scaler = _load_artifacts()

    vector = np.array([[float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]])
    scaled = scaler.transform(vector)

    raw_anomaly_score = float(model.score_samples(scaled)[0])
    base_score = map_to_risk_scale(raw_anomaly_score)

    return {
        "raw_anomaly_score": round(raw_anomaly_score, 4),
        "base_risk_score": round(base_score, 2),
        "base_risk_category": risk_category(base_score),
    }


def score_batch(rows: list[dict[str, float]]) -> list[dict[str, Any]]:
    """Score multiple feature rows in one pass (used by the pipeline orchestrator)."""
    if not rows:
        return []
    model, scaler = _load_artifacts()

    matrix = np.array([[float(r.get(col, 0.0)) for col in FEATURE_COLUMNS] for r in rows])
    scaled = scaler.transform(matrix)
    raw_scores = model.score_samples(scaled)

    results = []
    for raw in raw_scores:
        base_score = map_to_risk_scale(float(raw))
        results.append({
            "raw_anomaly_score": round(float(raw), 4),
            "base_risk_score": round(base_score, 2),
            "base_risk_category": risk_category(base_score),
        })
    return results
