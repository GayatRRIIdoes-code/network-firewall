# Network Firewall - Stage 1: Core Rule Engine

This is **Stage 1** of the network firewall project. It implements the core rule-based packet filtering engine with JSON configuration, logging, and comprehensive tests.

## What Stage 1 Includes

### Core Files

1. **firewall/rules.py**
   - `FirewallRule` class: Represents a single rule with matching logic
   - `RuleEngine` class: Loads rules from JSON and evaluates packets
   - Supports exact IP matching and CIDR network ranges
   - Supports protocol matching (TCP, UDP, ICMP, ANY)
   - Supports port-based filtering

2. **firewall/engine.py**
   - `FirewallEngine` class: Main interface for packet filtering
   - Integrates rule engine and logger
   - Returns decision (ALLOW/DENY) with matched rule name

3. **firewall/logger.py**
   - Configures file and console logging
   - Logs all packet decisions with timestamps
   - Stores logs in `logs/firewall.log`

4. **config/firewall_rules.json**
   - JSON configuration with default action and rules list
   - Includes 6 sample rules:
     - Allow HTTP (port 80)
     - Allow HTTPS (port 443)
     - Allow SSH only from admin IP
     - Deny Telnet (port 23)
     - Allow ICMP (for future rate limiting)
     - Deny unauthorized inbound (default)

5. **main.py**
   - Demonstrates firewall engine with sample packets
   - Does NOT capture live packets (Stage 2+)
   - Shows how rules are evaluated
   - Displays decisions and logs

6. **tests/test_rules.py**
   - 16 unit tests for rule matching
   - Tests rule evaluation logic
   - Tests engine decision making
   - Tests CIDR network matching
   - Tests rule ordering

## Installation & Setup

```bash
# Clone the repo
git clone https://github.com/GayatRRIIdoes-code/network-firewall.git
cd network-firewall

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running Stage 1

### Run the demonstration:
```bash
python3 main.py
```

This will:
- Load rules from config/firewall_rules.json
- Test 7 sample packets
- Display decisions for each packet
- Log all results to logs/firewall.log

### Run the tests:
```bash
pytest tests/test_rules.py -v
```

This will run 16 unit tests and display the results.

### View the logs:
```bash
cat logs/firewall.log
```

## Architecture Explanation

### Rule Matching Flow

```
1. Packet received (dict with src_ip, dst_ip, protocol, ports)
2. Engine iterates through rules in order
3. First rule to match is used
4. If no rule matches, DEFAULT action (DENY) is applied
5. Decision and rule name are logged
6. Result returned to caller
```

### Rule Configuration Format

```json
{
  "name": "rule_identifier",
  "action": "ALLOW" or "DENY",
  "protocol": "TCP", "UDP", "ICMP", or "ANY",
  "src_ip": "192.168.1.0/24" or "192.168.1.50" or "ANY",
  "dst_ip": "...",
  "src_port": 12345 or null,
  "dst_port": 80 or null,
  "description": "Human readable description"
}
```

### Key Features

- **Rule Ordering**: First matching rule wins
- **Default Deny**: Unmatched traffic is blocked
- **CIDR Support**: Rules can specify IP ranges (e.g., 192.168.0.0/16)
- **Wildcard Support**: ANY protocol matches all protocols
- **Flexible Matching**: Match on any combination of src/dst IP and port

## What's NOT Included in Stage 1

- ❌ Live packet capture (uses Scapy later)
- ❌ VPN integration
- ❌ ICMP rate limiting (stub for later)
- ❌ Network namespace testing
- ❌ Advanced packet inspection

## File Structure

```
network-firewall/
├── firewall/
│   ├── __init__.py          # Package exports
│   ├── rules.py             # Rule loading and matching
│   ├── engine.py            # Main firewall engine
│   └── logger.py            # Logging configuration
├── config/
│   └── firewall_rules.json  # Firewall policy rules
├── tests/
│   └── test_rules.py        # Unit tests (16 tests)
├── logs/                    # Log output directory
├── main.py                  # Demonstration script
├── requirements.txt         # Dependencies
└── README-STAGE-1.md        # This file
```

## Test Coverage

All 16 tests pass:

- ✅ Exact port matching
- ✅ Port mismatch detection
- ✅ Protocol matching
- ✅ Protocol mismatch detection
- ✅ Exact IP matching
- ✅ IP mismatch detection
- ✅ CIDR network matching
- ✅ CIDR range mismatch
- ✅ ANY protocol wildcard
- ✅ ICMP matching
- ✅ Engine HTTP allow
- ✅ Engine HTTPS allow
- ✅ Engine SSH from admin allow
- ✅ Engine SSH from unauthorized deny
- ✅ Engine Telnet deny
- ✅ Engine default deny

## Modifying Rules

Edit `config/firewall_rules.json` to add or modify rules. No Python code changes needed.

Example: Add a rule to block FTP:
```json
{
  "name": "deny_ftp",
  "action": "DENY",
  "protocol": "TCP",
  "dst_port": 21,
  "description": "Block FTP traffic"
}
```

## Next Stages

- **Stage 2**: Live packet capture with Scapy
- **Stage 3**: VPN integration with WireGuard
- **Stage 4**: ICMP rate limiting
- **Stage 5**: Real-world testing and deployment

## Dependencies

- Python 3.7+
- pytest >= 7.0 (for testing)

No external libraries required for the core firewall engine in Stage 1.
