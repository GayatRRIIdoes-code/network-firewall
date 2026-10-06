"""Test mode for packet processing without root privileges."""

import logging
from typing import Any, Dict, List, Callable, Optional
from scapy.all import IP, TCP, UDP, ICMP
from .packet import PacketProcessor
from .engine import FirewallEngine


class TestPacket:
    """Creates synthetic Scapy packets for testing."""

    @staticmethod
    def create_tcp_packet(
        src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Any:
        """Create a synthetic TCP packet.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port

        Returns:
            Scapy IP/TCP packet
        """
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)

    @staticmethod
    def create_udp_packet(
        src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Any:
        """Create a synthetic UDP packet.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port

        Returns:
            Scapy IP/UDP packet
        """
        return IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)

    @staticmethod
    def create_icmp_packet(src_ip: str, dst_ip: str) -> Any:
        """Create a synthetic ICMP packet.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address

        Returns:
            Scapy IP/ICMP packet
        """
        return IP(src=src_ip, dst=dst_ip) / ICMP(type=8, id=1)


class TestMode:
    """Safe test mode for packet processing without root privileges."""

    def __init__(self, rules_file: str = "config/firewall_rules.json"):
        """Initialize test mode.

        Args:
            rules_file: Path to firewall rules JSON file
        """
        self.engine = FirewallEngine(rules_file)
        self.processor = PacketProcessor()
        self.logger = logging.getLogger("firewall")
        self.results = []

    def process_packet(
        self, packet: Any, packet_name: str = ""
    ) -> tuple[str, str, Dict[str, Any]]:
        """Process a synthetic packet through the firewall.

        Args:
            packet: Scapy packet object
            packet_name: Optional name for display purposes

        Returns:
            Tuple of (decision, rule_name, packet_info)
        """
        # Extract packet information
        packet_info = self.processor.process_packet(packet)
        if packet_info is None:
            self.logger.warning(f"Could not process packet: {packet_name}")
            return ("ERROR", "INVALID_PACKET", {})

        # Filter through firewall engine
        decision, rule_name, log_msg = self.engine.filter_packet(packet_info)

        # Store result
        result = {
            "name": packet_name,
            "decision": decision,
            "rule": rule_name,
            "packet_info": packet_info,
        }
        self.results.append(result)

        return (decision, rule_name, packet_info)

    def process_packets(
        self, packets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process a list of test packets.

        Args:
            packets: List of dicts with 'name' and 'packet' keys

        Returns:
            List of results with decisions
        """
        self.results = []

        for test_case in packets:
            packet = test_case["packet"]
            name = test_case.get("name", "Unknown")
            self.process_packet(packet, name)

        return self.results

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all processed results."""
        return self.results

    def print_results(self) -> None:
        """Print results in a formatted table."""
        print("\n" + "="*90)
        print(f"{'Test Case':<30} {'Decision':<10} {'Rule':<30}")
        print("="*90)

        for result in self.results:
            name = result["name"]
            decision = result["decision"]
            rule = result["rule"]
            print(f"{name:<30} {decision:<10} {rule:<30}")

        print("="*90 + "\n")
