# Network Security using Firewalls

This project provides a lightweight, rule-based firewall built with Python 3 and Scapy for a simulated organization network. It inspects packets, applies rules in order, logs decisions, and integrates with a basic WireGuard-style VPN configuration.

## 1. Project overview

The firewall is designed for a controlled Ubuntu/Linux lab or VM environment. It provides a simple but practical student-friendly implementation of:

- packet capture and inspection
- rule matching by source/destination IP, port, protocol, and interface
- default deny behavior
- logging of all decisions
- VPN-aware traffic handling with a WireGuard-style example configuration

The project is intentionally modular and beginner-friendly. The rules are stored in a JSON file so they can be edited without changing Python code.

## 2. Architecture

The project is organized into small, focused modules:

- `main.py` — runs the firewall engine
- `firewall/engine.py` — packet capture, rule evaluation, and logging
- `firewall/rules.py` — JSON rule loading and rule matching logic
- `firewall/logger.py` — file-based logging configuration
- `firewall/vpn.py` — basic VPN interface and network detection
- `config/firewall_rules.json` — firewall policy configuration
- `config/wg0.conf` — example WireGuard configuration
- `tests/test_firewall.py` — validation tests for core firewall behavior

## 3. Firewall rule system

The firewall uses ordered rules. The first matching rule wins. If no rule matches, the engine applies the default action, which is `DENY`.

Rules are stored in `config/firewall_rules.json` and include examples for:

- allowing HTTP on port 80
- allowing HTTPS on port 443
- allowing SSH only from an authorized admin IP
- allowing SSH from a WireGuard VPN subnet
- denying Telnet traffic on port 23
- denying unauthorized inbound traffic to a protected internal subnet
- blocking excessive ICMP ping traffic

Rule fields include:

- `name`
- `action` (`ALLOW` or `DENY`)
- `protocol` (`TCP`, `UDP`, `ICMP`, or `ANY`)
- `src_ip` and `dst_ip`
- `src_port` and `dst_port`
- `vpn_only`
- `icmp_rate_limit`

## 4. VPN integration

This project includes a basic VPN security component that is intentionally separated from the core firewall rule engine. The firewall checks whether a packet is traversing a VPN interface or a VPN address range, and then applies the same policy logic to that traffic.

The VPN example uses a WireGuard-style configuration stored at `config/wg0.conf`.

This is a practical student-level integration because it:

- demonstrates how a VPN can be part of the network design
- shows traffic filtering on VPN interfaces
- keeps the cryptography implementation out of scope
- avoids writing custom encryption logic from scratch

## 5. Installation

On Ubuntu/Linux, install Python 3 and the project dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
cd network-firewall
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 6. Configuration

The central firewall policy is in:

`config/firewall_rules.json`

Example rule entries are already included. You may update them by editing the JSON file.

The VPN configuration example is in:

`config/wg0.conf`

This file is not a full production WireGuard deployment, but it provides a realistic example for a student project and allows the firewall to recognize VPN traffic.

## 7. Running the firewall

Run the firewall in a controlled Linux VM or network namespace. For example:

```bash
sudo python3 main.py --interface eth0 --timeout 30
```

Or run it with a specific network interface:

```bash
sudo python3 main.py --interface wg0 --timeout 30
```

Important notes:

- Packet capture requires root privileges.
- Use a Linux VM or a network namespace for testing.
- Avoid running against a production system.
- For a local lab, create isolated interfaces or use packet generation tools inside a VM.

## 8. Testing methodology

The test suite in `tests/test_firewall.py` validates:

- allowed HTTP traffic
- allowed HTTPS traffic
- authorized SSH access
- unauthorized SSH access
- telnet blocking
- ICMP rate limiting
- default deny behavior
- VPN traffic filtering

Run tests with:

```bash
pytest -q
```

## 9. Expected results

A correctly configured firewall should:

- allow standard web traffic on ports 80 and 443
- allow SSH only from the authorized admin IP or VPN subnet
- deny Telnet on port 23
- deny unauthorized inbound traffic to protected ranges
- block excessive ping traffic while allowing normal diagnostic traffic
- deny all unmatched traffic by default
- log each decision to `logs/firewall.log`

## 10. Limitations and future enhancements

### Limitations

- This is a student-friendly simulation, not a full enterprise firewall.
- It operates on packet inspection and does not implement a full stateful firewall.
- It does not provide real-time DPI or advanced threat detection.
- VPN support is intentionally lightweight and safe for educational use.

### Future enhancements

- add explicit stateful connection tracking
- support more advanced firewall rule matching with logging categories
- add a dashboard or web interface
- integrate with actual WireGuard or Linux nftables/iptables rules
- add deeper rate limiting and anomaly detection

## Running in a safe lab environment

For realistic testing, use a local Ubuntu/Linux VM or a network namespace. This project is meant to be run inside a controlled environment, not on a host used for normal internet access.

A common setup is:

```bash
sudo ip netns add firewall-lab
sudo ip netns exec firewall-lab bash
```

Then run the firewall inside the namespace and generate controlled traffic with tools like `ping`, `nc`, or Scapy.

## Summary

This project demonstrates how to build a beginner-friendly but realistic firewall in Python using Scapy, while also including a safe, minimal VPN integration example. It is designed for classroom use, labs, and practical demos on Ubuntu/Linux.
