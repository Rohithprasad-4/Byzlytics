"""Extract normalized event fields from a captured Scapy packet.

Kept independent of Scapy imports at module scope so it can be unit
tested (and the rest of the capture package can be imported) even on
machines where Scapy/Npcap are not installed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_packet(packet: Any) -> dict[str, Any] | None:
    """Convert a Scapy packet into a normalized event dict, or None if
    it doesn't match DNS (UDP:53), TCP (with SYN flag), or ICMP."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    base = {
        "timestamp": timestamp,
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "packet_size": int(len(packet)),
        "source_port": None,
        "destination_port": None,
        "protocol": "OTHER",
    }

    if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53:
        base["protocol"] = "DNS"
        base["source_port"] = int(packet[UDP].sport)
        base["destination_port"] = int(packet[UDP].dport)
        return base

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if int(tcp_layer.flags) & 0x02:  # SYN flag set
            base["protocol"] = "TCP"
            base["source_port"] = int(tcp_layer.sport)
            base["destination_port"] = int(tcp_layer.dport)
            return base
        return None

    if packet.haslayer(ICMP):
        base["protocol"] = "ICMP"
        return base

    return None


def parse_packet_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse an already-dict-shaped packet description (used by tests and
    by the simulator, which does not require Scapy or raw socket access)."""
    return {
        "timestamp": raw.get("timestamp") or datetime.now(timezone.utc),
        "source_ip": raw["source_ip"],
        "destination_ip": raw["destination_ip"],
        "packet_size": int(raw.get("packet_size", 64)),
        "source_port": raw.get("source_port"),
        "destination_port": raw.get("destination_port"),
        "protocol": str(raw.get("protocol", "OTHER")).upper(),
    }
