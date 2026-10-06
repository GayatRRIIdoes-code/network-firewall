"""Main firewall demonstration with sample packets."""

from firewall.engine import FirewallEngine


def print_packet_info(packet, decision, rule, log_msg):
    """Display packet filtering result."""
    print("\n" + "="*70)
    print(f"Packet: {packet['src_ip']}:{packet.get('src_port', 'N/A')} -> {packet['dst_ip']}:{packet.get('dst_port', 'N/A')}")
    print(f"Protocol: {packet['protocol']}")
    print(f"Decision: {decision} (Rule: {rule})")
    print("="*70)


def main():
    """Run firewall demonstration."""
    print("\n" + "*"*70)
    print("FIREWALL ENGINE DEMONSTRATION - STAGE 1")
    print("*"*70)

    # Initialize firewall engine
    engine = FirewallEngine("config/firewall_rules.json")

    print("\nLoaded Rules:")
    for rule in engine.get_rules():
        print(f"  - {rule.name}: {rule.action} | Protocol: {rule.protocol} | "
              f"Port: {rule.dst_port or 'N/A'} | Description: {rule.description}")

    # Test packets
    test_packets = [
        {
            "name": "HTTP Request",
            "packet": {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 80,
            },
        },
        {
            "name": "HTTPS Request",
            "packet": {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "src_port": 50001,
                "dst_port": 443,
            },
        },
        {
            "name": "SSH from Authorized Admin",
            "packet": {
                "src_ip": "192.168.1.50",
                "dst_ip": "10.10.10.5",
                "protocol": "TCP",
                "src_port": 60000,
                "dst_port": 22,
            },
        },
        {
            "name": "SSH from Unauthorized IP",
            "packet": {
                "src_ip": "203.0.113.9",
                "dst_ip": "10.10.10.5",
                "protocol": "TCP",
                "src_port": 60000,
                "dst_port": 22,
            },
        },
        {
            "name": "Telnet Traffic",
            "packet": {
                "src_ip": "203.0.113.9",
                "dst_ip": "10.10.10.5",
                "protocol": "TCP",
                "src_port": 40000,
                "dst_port": 23,
            },
        },
        {
            "name": "ICMP Ping",
            "packet": {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "ICMP",
            },
        },
        {
            "name": "Unknown Traffic (Default Deny)",
            "packet": {
                "src_ip": "198.51.100.100",
                "dst_ip": "10.10.10.20",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 8080,
            },
        },
    ]

    print("\n" + "*"*70)
    print("FILTERING TEST PACKETS")
    print("*"*70)

    # Filter each packet
    for test in test_packets:
        decision, rule, log_msg = engine.filter_packet(test["packet"])
        print_packet_info(test["packet"], decision, rule, log_msg)

    print("\n" + "*"*70)
    print("Demonstration Complete. Check logs/firewall.log for detailed logs.")
    print("*"*70 + "\n")


if __name__ == "__main__":
    main()
