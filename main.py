"""Main firewall demonstration with Scapy packet inspection."""

import argparse
import sys
from firewall.engine import FirewallEngine
from firewall.capture import PacketCapture
from firewall.test_mode import TestMode, TestPacket


def demo_test_mode():
    """Run firewall in test mode with synthetic packets."""
    print("\n" + "*" * 90)
    print("FIREWALL ENGINE - TEST MODE (No Root Required)")
    print("*" * 90)

    # Initialize test mode
    test_mode = TestMode("config/firewall_rules.json")

    print("\nLoaded Rules:")
    for rule in test_mode.engine.get_rules():
        print(
            f"  - {rule.name}: {rule.action} | Protocol: {rule.protocol} | "
            f"Port: {rule.dst_port or 'N/A'} | Description: {rule.description}"
        )

    # Create test packets
    test_packets = [
        {
            "name": "HTTP Request",
            "packet": TestPacket.create_tcp_packet(
                "192.168.1.10", "8.8.8.8", 50000, 80
            ),
        },
        {
            "name": "HTTPS Request",
            "packet": TestPacket.create_tcp_packet(
                "192.168.1.10", "8.8.8.8", 50001, 443
            ),
        },
        {
            "name": "SSH from Authorized Admin",
            "packet": TestPacket.create_tcp_packet(
                "192.168.1.50", "10.10.10.5", 60000, 22
            ),
        },
        {
            "name": "SSH from Unauthorized IP",
            "packet": TestPacket.create_tcp_packet(
                "203.0.113.9", "10.10.10.5", 60000, 22
            ),
        },
        {
            "name": "Telnet Traffic",
            "packet": TestPacket.create_tcp_packet(
                "203.0.113.9", "10.10.10.5", 40000, 23
            ),
        },
        {
            "name": "ICMP Ping",
            "packet": TestPacket.create_icmp_packet("192.168.1.10", "8.8.8.8"),
        },
        {
            "name": "DNS Query (UDP)",
            "packet": TestPacket.create_udp_packet(
                "192.168.1.100", "8.8.8.8", 54321, 53
            ),
        },
        {
            "name": "Unknown TCP Traffic (Default Deny)",
            "packet": TestPacket.create_tcp_packet(
                "198.51.100.100", "10.10.10.20", 50000, 8080
            ),
        },
    ]

    print("\n" + "*" * 90)
    print("PROCESSING TEST PACKETS")
    print("*" * 90)

    # Process all packets
    test_mode.process_packets(test_packets)

    # Display results
    test_mode.print_results()

    print("Test mode complete. Check logs/firewall.log for detailed logs.")


def demo_live_capture(interface, timeout, packet_filter):
    """Run firewall in live capture mode (requires root)."""
    print("\n" + "*" * 90)
    print(f"FIREWALL ENGINE - LIVE PACKET CAPTURE")
    print(f"Interface: {interface}")
    print(f"Timeout: {timeout}s" if timeout else "Timeout: None (continuous)")
    print("*" * 90)

    print("\n[!] This requires root privileges. Run with: sudo python3 main.py --live")
    print("    Press Ctrl+C to stop.\n")

    try:
        capture = PacketCapture(
            interface=interface, rules_file="config/firewall_rules.json"
        )
        capture.start_capture(timeout=timeout, packet_filter=packet_filter)
        print(
            f"\nCapture complete. Processed {capture.get_packet_count()} packets."
        )
    except PermissionError:
        print("\n[ERROR] Root privileges required. Run with: sudo python3 main.py --live")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Firewall with Scapy packet inspection"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run in live capture mode (requires root)",
    )
    parser.add_argument(
        "--interface", default="eth0", help="Network interface to sniff on"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Capture timeout in seconds"
    )
    parser.add_argument(
        "--filter", default="", help="BPF packet filter (e.g., 'tcp port 80')"
    )
    parser.add_argument(
        "--rules",
        default="config/firewall_rules.json",
        help="Path to firewall rules JSON file",
    )

    args = parser.parse_args()

    if args.live:
        # Live capture mode
        demo_live_capture(args.interface, args.timeout, args.filter)
    else:
        # Test mode (default)
        demo_test_mode()


if __name__ == "__main__":
    main()
