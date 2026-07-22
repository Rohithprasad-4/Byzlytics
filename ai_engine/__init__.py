"""SecureGate AI — AI Risk Assessment Engine (Phase 7).

Combines the Isolation Forest anomaly score with rule-based domain
bonuses to produce a final 0-100 risk score, then generates a
plain-English explanation (GPT-3.5, falling back to a self-contained
rule-based template engine when no API key/network is available).
"""
