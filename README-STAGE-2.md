# Network Firewall - Stage 2: Scapy Packet Inspection

This is **Stage 2** of the network firewall project. It adds live packet capture and inspection using Scapy, while keeping the core rule engine from Stage 1 intact.

## What Stage 2 Adds

### New Files

1. **firewall/packet.py**
   - `PacketProcessor` class: Extracts packet information from Scapy packets
   - Handles TCP, UDP, and ICMP protocols
   - Returns normalized packet dictionaries
   - Non-invasive design that doesn't modify packets

2. **firewall/capture.py**
   - `PacketCapture` class: Captures live packets from network interfaces
   - Integrates packet processor with firewall engine
   - Supports packet counting and filtering
   - Requires root privileges for live capture

3. **firewall/test_mode.py**
   - `TestPacket` class: Creates synthetic Scapy packets for testing
   - `TestMode` class: Processes test packets without root privileges
   - Safe testing environment for rule validation
   - Formatted result reporting

4. **tests/test_packet_parsing.py**
   - 10+ unit tests for packet extraction
   - Tests for TCP, UDP, and ICMP parsing
   - Tests for multiple packets and different protocols
   - Tests non-IP packet handling

### Modified Files

- **firewall/__init__.py** - Updated exports for new classes
- **main.py** - Now supports both test mode and live capture mode
- **requirements.txt** - Added Scapy dependency

## Installation & Setup

```bash
# Navigate to project directory
cd network-firewall

# Create/activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies (including Scapy)
pip install -r requirements.txt
```

## Running Stage 2

### Test Mode (No Root Required)

Default mode - tests firewall with synthetic packets:

```bash
python3 main.py
```

Output:
- Displays all loaded rules
- Processes 8 test packets
- Shows ALLOW/DENY decisions
- Logs results to logs/firewall.log

### Live Capture Mode (Requires Root)

Capture and filter real network traffic:

```bash
sudo python3 main.py --live
```

Options:
```bash
# Capture on specific interface
sudo python3 main.py --live --interface wlan0

# Set timeout (default 30 seconds)
sudo python3 main.py --live --timeout 60

# Apply BPF filter (optional)
sudo python3 main.py --live --filter "tcp port 80"

# Custom rules file
sudo python3 main.py --live --rules custom_rules.json
```

### Run Tests

```bash
# Run all tests
pytest -v

# Run only packet parsing tests
pytest tests/test_packet_parsing.py -v

# Run only rule tests
pytest tests/test_rules.py -v
```

### View Logs

```bash
cat logs/firewall.log
```

## Architecture

### Packet Processing Flow

```
1. Live Packet Captured (Scapy)
2. PacketProcessor.extract_packet_info()
   - Check for IP layer
   - Detect protocol (TCP/UDP/ICMP)
   - Extract IPs and ports
   - Return normalized dict
3. FirewallEngine.filter_packet()
   - Match against rules
   - Apply first matching rule
   - Log decision
4. Result Returned
   - ALLOW or DENY
   - Matched rule name
```

### Test Mode Architecture

```
1. Create Synthetic Packet (TestPacket)
2. TestMode.process_packet()
   - Process packet through engine
   - Store result
3. Display Results
   - Formatted table output
```

## Packet Information Format

Extracted packet information (normalized dict):

```python
{
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",  # or UDP, ICMP, UNKNOWN
    "src_port": 50000,   # None for ICMP
    "dst_port": 80       # None for ICMP
}
```

## Key Features

- ✅ **Live packet capture** with Scapy
- ✅ **Safe test mode** (no root required)
- ✅ **TCP/UDP/ICMP support**
- ✅ **Protocol extraction** with ports
- ✅ **Non-invasive** (doesn't modify packets)
- ✅ **Rule integration** with Stage 1 engine
- ✅ **Comprehensive logging**
- ✅ **Flexible filtering** (BPF support)
- ✅ **Modular design** (separate concerns)

## Test Coverage

Stage 2 adds 10+ tests for packet parsing:

- ✅ TCP packet extraction
- ✅ UDP packet extraction
- ✅ ICMP packet extraction
- ✅ TCP with various ports
- ✅ UDP DNS traffic
- ✅ ICMP ping packets
- ✅ Processor process_packet() method
- ✅ Non-IP packet handling
- ✅ TCP SSH packets
- ✅ Multiple protocols in sequence

## Safe Lab Testing

### In a Virtual Machine

```bash
# On Ubuntu/Linux VM
sudo python3 main.py --live --interface eth0 --timeout 30
```

### Using Network Namespace (Safest)

```bash
# Create isolated namespace
sudo ip netns add firewall-lab

# Run firewall in namespace
sudo ip netns exec firewall-lab python3 main.py --live
```

### With Test Mode

```bash
# No privileges needed - just test rules
python3 main.py
```

## Generating Test Traffic

In another terminal, generate traffic for the firewall to inspect:

```bash
# Ping
ping 8.8.8.8

# HTTP (if your system allows)
curl http://example.com

# DNS query
nslookup google.com 8.8.8.8
```

## Important Notes

### Root Privileges

Live packet capture requires root:

```bash
sudo python3 main.py --live
```

### Network Interface

Common interfaces:
- `eth0` - Ethernet
- `wlan0` - WiFi
- `lo` - Loopback

List available:
```bash
ip link show
```

### BPF Filters

Optional packet filters:

```bash
# HTTP only
sudo python3 main.py --live --filter "tcp port 80"

# SSH only
sudo python3 main.py --live --filter "tcp port 22"

# DNS only
sudo python3 main.py --live --filter "udp port 53"

# ICMP ping
sudo python3 main.py --live --filter "icmp"
```

## Troubleshooting

### "Permission Denied" Error

```bash
# Need root for live capture
sudo python3 main.py --live
```

### "Interface not found" Error

```bash
# Check available interfaces
ip link show

# Use correct interface
sudo python3 main.py --live --interface wlan0
```

### No packets captured

```bash
# Generate traffic in another terminal
ping 8.8.8.8

# Or run test mode instead
python3 main.py  # No root needed
```

## What's NOT Included in Stage 2

- ❌ VPN integration (Stage 3)
- ❌ ICMP rate limiting (Stage 3)
- ❌ Stateful firewall (future)
- ❌ DPI (deep packet inspection)
- ❌ Advanced threat detection

## File Structure

```
network-firewall/
├── firewall/
│   ├── __init__.py
│   ├── engine.py           # Stage 1
│   ├── rules.py            # Stage 1
│   ├── logger.py           # Stage 1
│   ├── packet.py           # Stage 2 (NEW)
│   ├── capture.py          # Stage 2 (NEW)
│   └── test_mode.py        # Stage 2 (NEW)
├── config/
│   └── firewall_rules.json # Stage 1
├── tests/
│   ├── test_rules.py
│   └── test_packet_parsing.py  # Stage 2 (NEW)
├── logs/
├── main.py                 # Updated
├── requirements.txt        # Updated
├── README-STAGE-1.md
└── README-STAGE-2.md       # This file
```

## Next Stages

- **Stage 3**: VPN integration and ICMP rate limiting
- **Stage 4**: Advanced filtering and stateful inspection
- **Stage 5**: Real-world deployment and performance tuning

## Dependencies

- Python 3.7+
- Scapy 2.5.0
- pytest >= 7.0 (for testing)

## Summary

Stage 2 completes the core firewall implementation:
- Packet capture with Scapy ✅
- Protocol detection (TCP/UDP/ICMP) ✅
- Safe test mode ✅
- Live filtering ✅
- Comprehensive tests ✅

The firewall is now fully functional for packet inspection and rule-based filtering.
