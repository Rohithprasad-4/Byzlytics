"""SecureGate AI — Network traffic acquisition layer (Phase 3).

Captures LAN traffic with Scapy and persists parsed events to
PostgreSQL. Requires Npcap (Windows) or libpcap (Linux/macOS) and, on
most platforms, elevated privileges to open a raw socket.
"""
