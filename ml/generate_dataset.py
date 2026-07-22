"""Phase 6 — Synthetic training dataset generator.

Produces a labelled CSV (label used only for offline ROC-AUC evaluation;
the Isolation Forest itself trains unsupervised) of 500 records: 400
"normal" LAN traffic profiles and 100 "anomalous" profiles (DNS
flooding, port scanning, ICMP sweeping, dangerous-port access, and
off-hours beaconing). Run:

    python -m ml.generate_dataset
"""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import DANGEROUS_PORTS, FEATURE_COLUMNS

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
OUTPUT_FILE = MODELS_DIR / "training_dataset.csv"

RANDOM_SEED = 42
NORMAL_COUNT = 400
ANOMALOUS_COUNT = 100

SAFE_PORTS = [80, 443, 53, 8443, 51234, 51235, 60000, 60001]


def _normal_record(rng: random.Random) -> dict:
    protocol = rng.choices(["dns", "tcp", "icmp"], weights=[0.5, 0.4, 0.1])[0]
    hour = rng.randint(7, 21)  # business-ish hours, mostly
    requests_60 = rng.uniform(5, 60)
    requests_15 = requests_60 * rng.uniform(0.15, 0.35)
    unique_60 = rng.uniform(1, 8)
    unique_15 = unique_60 * rng.uniform(0.2, 0.5)
    avg_size = rng.uniform(64, 512)
    packet_size = max(20, rng.gauss(avg_size, avg_size * 0.1))
    dest_port = rng.choice(SAFE_PORTS)

    return {
        "packet_size": round(packet_size, 2),
        "source_port": rng.randint(1024, 65535),
        "destination_port": dest_port,
        "protocol_dns": int(protocol == "dns"),
        "protocol_tcp": int(protocol == "tcp"),
        "protocol_icmp": int(protocol == "icmp"),
        "is_dangerous_port": int(dest_port in DANGEROUS_PORTS),
        "hour_of_day": hour,
        "day_of_week": rng.randint(0, 6),
        "is_night": int(hour < 6 or hour >= 22),
        "is_business_hours": int(9 <= hour <= 18),
        "requests_last_15min": round(requests_15, 2),
        "requests_last_60min": round(requests_60, 2),
        "unique_destinations_15min": round(unique_15, 2),
        "unique_destinations_60min": round(unique_60, 2),
        "avg_packet_size_ip": round(avg_size, 2),
        "deviation_score": round(abs(packet_size - avg_size) / max(avg_size, 1), 4),
        "historical_avg_requests_per_hour": round(requests_60 * rng.uniform(0.8, 1.2), 2),
        "request_rate_ratio": round(rng.uniform(0.7, 1.3), 3),
        "is_known_device": rng.choices([0, 1], weights=[0.2, 0.8])[0],
        "is_new_device": rng.choices([0, 1], weights=[0.85, 0.15])[0],
        "label": 0,
    }


def _anomalous_record(rng: random.Random) -> dict:
    scenario = rng.choice(["dns_flood", "port_scan", "icmp_sweep", "dangerous_port", "night_beacon"])
    hour = rng.randint(0, 23)
    dest_port = rng.choice(SAFE_PORTS)
    avg_size = rng.uniform(64, 512)
    packet_size = avg_size
    requests_60 = rng.uniform(20, 60)
    unique_60 = rng.uniform(1, 8)
    protocol = "tcp"

    if scenario == "dns_flood":
        protocol = "dns"
        requests_60 = rng.uniform(120, 400)
        unique_60 = rng.uniform(1, 5)
    elif scenario == "port_scan":
        protocol = "tcp"
        unique_60 = rng.uniform(20, 60)
        requests_60 = unique_60 * rng.uniform(1.0, 1.5)
    elif scenario == "icmp_sweep":
        protocol = "icmp"
        unique_60 = rng.uniform(15, 40)
        requests_60 = unique_60 * rng.uniform(1.0, 2.0)
    elif scenario == "dangerous_port":
        protocol = "tcp"
        dest_port = rng.choice(sorted(DANGEROUS_PORTS))
        requests_60 = rng.uniform(10, 80)
    elif scenario == "night_beacon":
        hour = rng.choice([0, 1, 2, 3, 4, 5])
        requests_60 = rng.uniform(30, 150)
        packet_size = avg_size * rng.uniform(3, 8)

    requests_15 = requests_60 * rng.uniform(0.3, 0.6)
    unique_15 = unique_60 * rng.uniform(0.3, 0.6)

    return {
        "packet_size": round(packet_size, 2),
        "source_port": rng.randint(1024, 65535),
        "destination_port": dest_port,
        "protocol_dns": int(protocol == "dns"),
        "protocol_tcp": int(protocol == "tcp"),
        "protocol_icmp": int(protocol == "icmp"),
        "is_dangerous_port": int(dest_port in DANGEROUS_PORTS),
        "hour_of_day": hour,
        "day_of_week": rng.randint(0, 6),
        "is_night": int(hour < 6 or hour >= 22),
        "is_business_hours": int(9 <= hour <= 18),
        "requests_last_15min": round(requests_15, 2),
        "requests_last_60min": round(requests_60, 2),
        "unique_destinations_15min": round(unique_15, 2),
        "unique_destinations_60min": round(unique_60, 2),
        "avg_packet_size_ip": round(avg_size, 2),
        "deviation_score": round(abs(packet_size - avg_size) / max(avg_size, 1), 4),
        "historical_avg_requests_per_hour": round(requests_60 * rng.uniform(0.2, 0.4), 2),
        "request_rate_ratio": round(requests_60 / max(requests_60 * rng.uniform(0.2, 0.4), 1), 3),
        "is_known_device": rng.choices([0, 1], weights=[0.6, 0.4])[0],
        "is_new_device": rng.choices([0, 1], weights=[0.4, 0.6])[0],
        "label": 1,
    }


def generate_dataset(seed: int = RANDOM_SEED) -> pd.DataFrame:
    rng = random.Random(seed)
    np.random.seed(seed)

    records = [_normal_record(rng) for _ in range(NORMAL_COUNT)]
    records += [_anomalous_record(rng) for _ in range(ANOMALOUS_COUNT)]
    rng.shuffle(records)

    df = pd.DataFrame(records)
    ordered_columns = FEATURE_COLUMNS + ["label"]
    return df[ordered_columns]


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = generate_dataset()
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Generated {len(df)} records ({NORMAL_COUNT} normal / {ANOMALOUS_COUNT} anomalous)")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
