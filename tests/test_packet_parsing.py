"""Unit tests for Scapy packet parsing."""

import pytest
from firewall.packet import PacketProcessor
from firewall.test_mode import TestPacket
from scapy.all import IP, TCP, UDP, ICMP


class TestPacketExtraction:
    """Test packet information extraction from Scapy packets."""

    def test_tcp_packet_extraction(self):
        """Test extracting information from a TCP packet."""
        # Create a synthetic TCP packet
        packet = TestPacket.create_tcp_packet(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=80,
        )

        # Process the packet
        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        # Verify extracted information
        assert result is not None
        assert result["src_ip"] == "192.168.1.10"
        assert result["dst_ip"] == "8.8.8.8"
        assert result["protocol"] == "TCP"
        assert result["src_port"] == 50000
        assert result["dst_port"] == 80

    def test_udp_packet_extraction(self):
        """Test extracting information from a UDP packet."""
        # Create a synthetic UDP packet
        packet = TestPacket.create_udp_packet(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=50001,
            dst_port=53,
        )

        # Process the packet
        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        # Verify extracted information
        assert result is not None
        assert result["src_ip"] == "192.168.1.10"
        assert result["dst_ip"] == "8.8.8.8"
        assert result["protocol"] == "UDP"
        assert result["src_port"] == 50001
        assert result["dst_port"] == 53

    def test_icmp_packet_extraction(self):
        """Test extracting information from an ICMP packet."""
        # Create a synthetic ICMP packet
        packet = TestPacket.create_icmp_packet(
            src_ip="192.168.1.10", dst_ip="8.8.8.8"
        )

        # Process the packet
        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        # Verify extracted information
        assert result is not None
        assert result["src_ip"] == "192.168.1.10"
        assert result["dst_ip"] == "8.8.8.8"
        assert result["protocol"] == "ICMP"
        assert result["src_port"] is None
        assert result["dst_port"] is None

    def test_tcp_packet_with_different_ports(self):
        """Test TCP packet extraction with various port numbers."""
        # HTTPS traffic
        packet = TestPacket.create_tcp_packet(
            src_ip="203.0.113.5", dst_ip="10.10.10.5", src_port=60000, dst_port=443
        )

        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        assert result["dst_port"] == 443
        assert result["protocol"] == "TCP"

    def test_udp_dns_packet(self):
        """Test UDP packet extraction for DNS (port 53)."""
        packet = TestPacket.create_udp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
        )

        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        assert result["protocol"] == "UDP"
        assert result["dst_port"] == 53
        assert result["src_ip"] == "192.168.1.100"

    def test_icmp_ping_packet(self):
        """Test ICMP ping packet extraction."""
        packet = TestPacket.create_icmp_packet(
            src_ip="192.168.1.50", dst_ip="1.1.1.1"
        )

        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        assert result["protocol"] == "ICMP"
        assert result["src_ip"] == "192.168.1.50"
        assert result["dst_ip"] == "1.1.1.1"

    def test_packet_processor_process_method(self):
        """Test PacketProcessor.process_packet method."""
        packet = TestPacket.create_tcp_packet(
            src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=50000, dst_port=80
        )

        processor = PacketProcessor()
        result = processor.process_packet(packet)

        assert result is not None
        assert result["protocol"] == "TCP"
        assert result["dst_port"] == 80

    def test_non_ip_packet_returns_none(self):
        """Test that non-IP packets return None."""
        # Create a packet without IP layer (just Ethernet, for example)
        # For testing purposes, we'll use a packet that doesn't have IP
        from scapy.all import Ether

        packet = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")

        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        assert result is None

    def test_tcp_ssh_packet(self):
        """Test TCP packet for SSH (port 22)."""
        packet = TestPacket.create_tcp_packet(
            src_ip="192.168.1.50",
            dst_ip="10.10.10.5",
            src_port=60000,
            dst_port=22,
        )

        processor = PacketProcessor()
        result = processor.extract_packet_info(packet)

        assert result["protocol"] == "TCP"
        assert result["dst_port"] == 22
        assert result["src_ip"] == "192.168.1.50"

    def test_multiple_packets_different_protocols(self):
        """Test extracting multiple packets with different protocols."""
        processor = PacketProcessor()
        results = []

        # TCP packet
        tcp_packet = TestPacket.create_tcp_packet(
            "192.168.1.1", "8.8.8.8", 50000, 80
        )
        results.append(processor.extract_packet_info(tcp_packet))

        # UDP packet
        udp_packet = TestPacket.create_udp_packet(
            "192.168.1.2", "8.8.8.8", 50001, 53
        )
        results.append(processor.extract_packet_info(udp_packet))

        # ICMP packet
        icmp_packet = TestPacket.create_icmp_packet("192.168.1.3", "8.8.8.8")
        results.append(processor.extract_packet_info(icmp_packet))

        assert results[0]["protocol"] == "TCP"
        assert results[1]["protocol"] == "UDP"
        assert results[2]["protocol"] == "ICMP"
