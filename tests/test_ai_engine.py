"""Unit tests for ai_engine.risk_scorer and ai_engine.rule_explainer."""

from __future__ import annotations

import pytest

from ai_engine.risk_scorer import score_event
from ai_engine.rule_explainer import generate_explanation

BASE_FEATURES = {
    "packet_size": 200, "source_port": 51000, "destination_port": 443,
    "protocol_dns": 0, "protocol_tcp": 1, "protocol_icmp": 0, "is_dangerous_port": 0,
    "hour_of_day": 14, "day_of_week": 2, "is_night": 0, "is_business_hours": 1,
    "requests_last_15min": 5, "requests_last_60min": 20, "unique_destinations_15min": 2,
    "unique_destinations_60min": 4, "avg_packet_size_ip": 190, "deviation_score": 0.05,
    "historical_avg_requests_per_hour": 22, "request_rate_ratio": 0.9,
    "is_known_device": 1, "is_new_device": 0,
    "protocol": "TCP", "source_ip": "192.168.1.10", "destination_ip": "8.8.8.8",
}


class TestRiskScorer:
    def test_normal_traffic_has_no_rule_bonuses(self):
        result = score_event(BASE_FEATURES)
        assert result["rule_adjustments"] == []

    def test_dangerous_port_adds_bonus(self):
        features = {**BASE_FEATURES, "is_dangerous_port": 1, "destination_port": 3389}
        result = score_event(features)
        rules = [a["rule"] for a in result["rule_adjustments"]]
        assert "dangerous_port" in rules

    def test_extreme_request_volume_adds_bonus(self):
        features = {**BASE_FEATURES, "requests_last_60min": 300}
        result = score_event(features)
        rules = [a["rule"] for a in result["rule_adjustments"]]
        assert "extreme_request_volume" in rules

    def test_scanning_behaviour_adds_bonus(self):
        features = {**BASE_FEATURES, "unique_destinations_60min": 20}
        result = score_event(features)
        rules = [a["rule"] for a in result["rule_adjustments"]]
        assert "scanning_behaviour" in rules

    def test_night_activity_adds_bonus(self):
        features = {**BASE_FEATURES, "is_night": 1, "hour_of_day": 2}
        result = score_event(features)
        rules = [a["rule"] for a in result["rule_adjustments"]]
        assert "night_activity" in rules

    def test_score_never_exceeds_100(self):
        features = {
            **BASE_FEATURES,
            "is_dangerous_port": 1,
            "deviation_score": 10,
            "requests_last_60min": 500,
            "unique_destinations_60min": 50,
            "is_business_hours": 0,
            "is_night": 1,
        }
        result = score_event(features)
        assert result["risk_score"] <= 100.0

    def test_risk_category_matches_score(self):
        result = score_event(BASE_FEATURES)
        if result["risk_score"] <= 30:
            assert result["risk_category"] == "Low"
        elif result["risk_score"] <= 60:
            assert result["risk_category"] == "Medium"
        else:
            assert result["risk_category"] == "High"


class TestRuleExplainer:
    def test_returns_three_required_keys(self):
        result = score_event(BASE_FEATURES)
        explanation = generate_explanation(
            BASE_FEATURES, result["risk_score"], result["risk_category"], result["rule_adjustments"]
        )
        assert set(["observation", "context", "recommendation"]).issubset(explanation.keys())

    def test_observation_mentions_source_ip(self):
        result = score_event(BASE_FEATURES)
        explanation = generate_explanation(
            BASE_FEATURES, result["risk_score"], result["risk_category"], result["rule_adjustments"]
        )
        assert BASE_FEATURES["source_ip"] in explanation["observation"]

    def test_low_risk_recommendation_says_no_action(self):
        explanation = generate_explanation(BASE_FEATURES, 10, "Low", [])
        assert "No action" in explanation["recommendation"]

    def test_high_risk_recommendation_says_block(self):
        explanation = generate_explanation(BASE_FEATURES, 85, "High", [{"rule": "dangerous_port", "delta": 15}])
        assert "Block" in explanation["recommendation"]

    def test_baseline_context_when_no_adjustments(self):
        explanation = generate_explanation(BASE_FEATURES, 10, "Low", [])
        assert "No unusual" in explanation["context"]
