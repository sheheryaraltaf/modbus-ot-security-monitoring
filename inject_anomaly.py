"""
inject_anomaly.py

Clones a known Modbus write packet from a real capture and changes its
source IP to an unauthorized address, to validate that detection logic
correctly flags writes that do not come from the expected master.

Usage:
    python inject_anomaly.py
"""

from scapy.all import rdpcap, wrpcap, IP, TCP

INPUT_PCAP = "ModbusTCP.pcap"
OUTPUT_PCAP = "ModbusTCP_injected.pcap"
ROGUE_SOURCE_IP = "192.168.50.99"   # not the known master (141.81.0.10)
WRITE_PACKET_INDEX = 34              # a known Write Multiple Coils packet

packets = rdpcap(INPUT_PCAP)

malicious = packets[WRITE_PACKET_INDEX].copy()
malicious[IP].src = ROGUE_SOURCE_IP

# Force checksum recalculation so the packet remains well-formed
del malicious[IP].chksum
if malicious.haslayer(TCP):
    del malicious[TCP].chksum

packets.append(malicious)
wrpcap(OUTPUT_PCAP, packets)

print(f"Done. Wrote {OUTPUT_PCAP} with one injected unauthorized write from {ROGUE_SOURCE_IP}.")
