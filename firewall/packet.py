"""Packet inspection and processing with Scapy."""

import logging
from typing import Any, Dict, Optional
from scapy.all import IP, TCP, UDP, ICMP


class PacketProcessor:
    """Extracts packet information from Scapy packets."""

    def __init__(self):
        self.logger = logging.getLogger("firewall")

    @staticmethod
    def extract_packet_info(packet: Any) -> Optional[Dict[str, Any]]:
        """Extract packet information from a Scapy packet.

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary with keys: src_ip, dst_ip, protocol, src_port, dst_port
            Returns None if packet cannot be processed
        """
        # Check if packet has IP layer
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        packet_info = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": "UNKNOWN",
            "src_port": None,
            "dst_port": None,
        }

        # Extract protocol-specific information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = int(tcp_layer.sport)
            packet_info["dst_port"] = int(tcp_layer.dport)

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = int(udp_layer.sport)
            packet_info["dst_port"] = int(udp_layer.dport)

        elif packet.haslayer(ICMP):
            packet_info["protocol"] = "ICMP"

        return packet_info

    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Process a Scapy packet and return normalized information.

        Args:
            packet: Scapy packet object

        Returns:
            Normalized packet dictionary or None if invalid
        """
        return self.extract_packet_info(packet)
