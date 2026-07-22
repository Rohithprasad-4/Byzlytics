"""Unit tests for ml.features, ml.generate_dataset, and ml.predict."""

from __future__ import annotations

import pytest

from ml.features import FEATURE_COLUMNS, DANGEROUS_PORTS
from ml.generate_dataset import generate_dataset
from ml.predict import map_to_risk_scale, risk_category


class TestFeatureSchema:
    def test_exactly_21_columns(self):
        assert len(FEATURE_COLUMNS) == 21

    def test_dangerous_ports_include_common_targets(self):
        for port in (22, 3389, 3306, 5432, 445):
            assert port in DANGEROUS_PORTS
        assert 51234 not in DANGEROUS_PORTS


class TestGenerateDataset:
    def test_produces_500_records(self):
        df = generate_dataset(seed=1)
        assert len(df) == 500

    def test_label_distribution(self):
        df = generate_dataset(seed=1)
        assert (df["label"] == 0).sum() == 400
        assert (df["label"] == 1).sum() == 100

    def test_columns_match_feature_schema_plus_label(self):
        df = generate_dataset(seed=1)
        assert list(df.columns) == FEATURE_COLUMNS + ["label"]

    def test_reproducible_with_same_seed(self):
        df1 = generate_dataset(seed=7)
        df2 = generate_dataset(seed=7)
        assert df1.equals(df2)


class TestRiskMapping:
    def test_risk_category_boundaries(self):
        assert risk_category(30) == "Low"
        assert risk_category(31) == "Medium"
        assert risk_category(60) == "Medium"
        assert risk_category(61) == "High"
        assert risk_category(100) == "High"
        assert risk_category(0) == "Low"

    def test_static_formula_clips_to_0_100(self, monkeypatch):
        from ml import predict

        monkeypatch.setattr(predict, "_load_score_range", lambda: None)
        assert map_to_risk_scale(0.5) == pytest.approx(0.0)
        assert map_to_risk_scale(-0.5) == pytest.approx(100.0)
        assert map_to_risk_scale(10.0) == 0.0
        assert map_to_risk_scale(-10.0) == 100.0
