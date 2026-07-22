"""Phase 3 — Scapy-based LAN packet sniffer.

Captures DNS (UDP:53), TCP SYN, and ICMP packets using a BPF pre-filter,
parses each into a normalized event, and saves it to PostgreSQL.

Run (requires Npcap on Windows / root or CAP_NET_RAW on Linux/macOS):
    python -m capture.capture --iface eth0

If Scapy or raw-socket capture isn't available in your environment
(e.g. inside a container, WSL without Npcap, or a VS Code dev
container), use --simulate to generate realistic synthetic traffic so
the rest of the pipeline (ML scoring, AI explanations, dashboard) can
be exercised end-to-end without special network privileges.
"""

from __future__ import annotations

import argparse
import logging
import random
import time
from datetime import datetime, timezone

from capture.db_handler import save_event
from capture.parser import parse_packet, parse_packet_dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

BPF_FILTER = "udp port 53 or (tcp[tcpflags] & tcp-syn != 0) or icmp"

SIMULATED_LAN_IPS = [f"192.168.1.{i}" for i in (10, 12, 20, 25, 33, 40, 50, 66)]
SIMULATED_EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "142.250.72.14", "104.16.85.20", "185.199.108.153"]


def _on_packet(packet, *, iface: str | None) -> None:
    try:
        event = parse_packet(packet)
        if event is None:
            return
        saved = save_event(event, capture_iface=iface)
        if saved:
            logger.info(
                "Captured %s %s -> %s (%d bytes)",
                event["protocol"], event["source_ip"], event["destination_ip"], event["packet_size"],
            )
    except Exception:
        logger.exception("Failed to process captured packet.")


def start_capture(iface: str | None = None, count: int = 0) -> None:
    """Start live capture using Scapy. Blocks until interrupted or `count` reached."""
    from scapy.all import sniff

    logger.info("Starting capture on interface=%s with filter='%s'", iface or "default", BPF_FILTER)
    sniff(
        iface=iface,
        filter=BPF_FILTER,
        prn=lambda pkt: _on_packet(pkt, iface=iface),
        store=False,
        count=count or 0,
    )


def _random_simulated_packet(rng: random.Random) -> dict:
    scenario = rng.choices(
        ["normal", "dns_burst", "port_scan", "icmp_sweep"],
        weights=[0.75, 0.1, 0.08, 0.07],
    )[0]
    source_ip = rng.choice(SIMULATED_LAN_IPS)

    if scenario == "dns_burst":
        return {
            "source_ip": source_ip,
            "destination_ip": "8.8.8.8",
            "protocol": "DNS",
            "source_port": rng.randint(1024, 65535),
            "destination_port": 53,
            "packet_size": rng.randint(60, 120),
        }
    if scenario == "port_scan":
        return {
            "source_ip": source_ip,
            "destination_ip": rng.choice(SIMULATED_LAN_IPS),
            "protocol": "TCP",
            "source_port": rng.randint(1024, 65535),
            "destination_port": rng.choice([21, 22, 23, 3389, 5900, 8080]),
            "packet_size": rng.randint(40, 80),
        }
    if scenario == "icmp_sweep":
        return {
            "source_ip": source_ip,
            "destination_ip": rng.choice(SIMULATED_LAN_IPS),
            "protocol": "ICMP",
            "packet_size": rng.randint(32, 64),
        }

    protocol = rng.choices(["DNS", "TCP", "ICMP"], weights=[0.5, 0.4, 0.1])[0]
    return {
        "source_ip": source_ip,
        "destination_ip": rng.choice(SIMULATED_EXTERNAL_IPS),
        "protocol": protocol,
        "source_port": rng.randint(1024, 65535) if protocol != "ICMP" else None,
        "destination_port": {"DNS": 53, "TCP": 443}.get(protocol),
        "packet_size": rng.randint(64, 512),
    }


def simulate_capture(*, duration_seconds: int = 60, packets_per_second: float = 3.0, seed: int | None = None) -> int:
    """Generate synthetic packets and persist them, for environments without raw-socket access."""
    rng = random.Random(seed)
    logger.info(
        "Simulating capture for %ds at ~%.1f pkt/s (no Scapy/Npcap required)",
        duration_seconds, packets_per_second,
    )
    saved_count = 0
    end_time = time.time() + duration_seconds
    interval = 1.0 / max(packets_per_second, 0.1)

    while time.time() < end_time:
        raw = _random_simulated_packet(rng)
        raw["timestamp"] = datetime.now(timezone.utc)
        event = parse_packet_dict(raw)
        if save_event(event, capture_iface="simulated"):
            saved_count += 1
        time.sleep(interval)

    logger.info("Simulation complete: %d events saved.", saved_count)
    return saved_count


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureGate AI packet capture.")
    parser.add_argument("--iface", default=None, help="Network interface to sniff on.")
    parser.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = unlimited).")
    parser.add_argument("--simulate", action="store_true", help="Generate synthetic traffic instead of live capture.")
    parser.add_argument("--duration", type=int, default=60, help="Simulation duration in seconds.")
    parser.add_argument("--rate", type=float, default=3.0, help="Simulated packets per second.")
    args = parser.parse_args()

    from backend.config import load_config
    from backend.database import init_db_pool

    init_db_pool(load_config().database)

    if args.simulate:
        simulate_capture(duration_seconds=args.duration, packets_per_second=args.rate)
        return

    try:
        start_capture(iface=args.iface, count=args.count)
    except ImportError:
        logger.error(
            "Scapy is not installed or Npcap/libpcap is unavailable. "
            "Install requirements.txt and Npcap (Windows) / libpcap (Linux/macOS), "
            "or re-run with --simulate."
        )
    except PermissionError:
        logger.error(
            "Permission denied opening a raw socket. Run as Administrator/root, "
            "or re-run with --simulate."
        )


if __name__ == "__main__":
    main()
