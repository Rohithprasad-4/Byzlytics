"""Phase 6 — Train the Isolation Forest anomaly detector.

Loads models/training_dataset.csv (generate it first with
`python -m ml.generate_dataset` if it does not exist), fits a
StandardScaler + IsolationForest pipeline, evaluates ROC-AUC on a 20%
held-out split using the synthetic labels (evaluation only — the model
itself is trained unsupervised on the full feature matrix), and
persists both artifacts with joblib.

Run:
    python -m ml.training
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_COLUMNS
from ml.generate_dataset import generate_dataset

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
DATASET_FILE = MODELS_DIR / "training_dataset.csv"
MODEL_FILE = MODELS_DIR / "model.pkl"
SCALER_FILE = MODELS_DIR / "scaler.pkl"
SCORE_RANGE_FILE = MODELS_DIR / "score_range.json"

# Isolation Forest configuration (Section 7.2 of the project report).
N_ESTIMATORS = 100
CONTAMINATION = 0.20  # matches the 100/500 synthetic anomaly ratio
RANDOM_STATE = 42


def _load_dataset() -> pd.DataFrame:
    if DATASET_FILE.exists():
        return pd.read_csv(DATASET_FILE)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = generate_dataset()
    df.to_csv(DATASET_FILE, index=False)
    return df


def train_model() -> dict:
    df = _load_dataset()
    X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    # score_samples: higher = more normal. Invert sign so higher = more anomalous,
    # which is what we correlate against the synthetic "label" for ROC-AUC only.
    raw_scores = -model.score_samples(X_test_scaled)
    auc = roc_auc_score(y_test, raw_scores)

    predictions = (model.predict(X_test_scaled) == -1).astype(int)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)

    # Empirically calibrate score_samples() -> 0-100 risk scale for THIS model,
    # since the actual output range depends on the training data and is rarely
    # the full theoretical [-0.5, +0.5] window. See ml/predict.py for the mapping.
    all_scaled = scaler.transform(X)
    all_scores = model.score_samples(all_scaled)
    score_min = float(np.percentile(all_scores, 1))
    score_max = float(np.percentile(all_scores, 99))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    SCORE_RANGE_FILE.write_text(json.dumps({"score_min": score_min, "score_max": score_max}))

    return {
        "roc_auc": auc,
        "classification_report": report,
        "model_path": str(MODEL_FILE),
        "scaler_path": str(SCALER_FILE),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "score_range": {"score_min": score_min, "score_max": score_max},
    }


def main() -> None:
    results = train_model()
    print(f"ROC-AUC score: {results['roc_auc']:.4f}")
    anomaly_metrics = results["classification_report"].get("1", {})
    print(f"Precision (anomaly): {anomaly_metrics.get('precision', 0):.3f}")
    print(f"Recall (anomaly):    {anomaly_metrics.get('recall', 0):.3f}")
    print(f"Model saved to  {results['model_path']}")
    print(f"Scaler saved to {results['scaler_path']}")


if __name__ == "__main__":
    main()
