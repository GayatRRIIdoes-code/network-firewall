from __future__ import annotations

import argparse

from firewall.engine import FirewallEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Rule-based packet firewall using Scapy")
    parser.add_argument("--interface", default="eth0", help="Network interface to inspect")
    parser.add_argument("--rules", default="config/firewall_rules.json", help="Path to firewall rules JSON file")
    parser.add_argument("--vpn-config", default="config/wg0.conf", help="Path to WireGuard-style VPN config")
    parser.add_argument("--timeout", type=float, default=30.0, help="How long to capture traffic in seconds")
    parser.add_argument("--count", type=int, default=0, help="Stop after N packets; 0 means no limit")
    args = parser.parse_args()

    engine = FirewallEngine(rules_path=args.rules, vpn_config_path=args.vpn_config)
    print(f"Starting firewall on interface: {args.interface}")
    engine.sniff_packets(interface=args.interface, count=args.count, timeout=args.timeout)


if __name__ == "__main__":
    main()
