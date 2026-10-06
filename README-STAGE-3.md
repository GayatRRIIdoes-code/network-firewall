# Network Firewall - Stage 3: Enhanced Firewall Logging

This is **Stage 3** of the network firewall project. It enhances logging with detailed packet information, structured log entries, and comprehensive error handling.

## What Stage 3 Adds

### New Files

1. **firewall/logging_config.py**
   - `FirewallLogFormatter` class: Custom log formatter for readable output
   - `PacketLogRecord` class: Structured packet log entry
   - `setup_firewall_logger()`: Configures file and console logging
   - `get_firewall_logger()`: Gets existing logger instance
   - Automatic log directory creation
   - Log file rotation (10 MB, 5 backups)

2. **tests/test_logging.py**
   - 13+ tests for logging functionality
   - Tests for PacketLogRecord formatting
   - Tests for FirewallEngine logging
   - Tests for statistics tracking
   - Tests for error handling

### Enhanced Files

- **firewall/engine.py** - Now includes comprehensive logging
- **firewall/__init__.py** - Exports logging classes
- **main.py** - Displays statistics and enhanced output

## Installation & Setup

```bash
# Navigate to project directory
cd network-firewall

# Create/activate virtual environment (if not already done)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running Stage 3

### Test Mode with Detailed Logging

```bash
python3 main.py
```

Output includes:
- Rules summary
- Test packet processing
- Detailed firewall statistics
- Logs written to `logs/firewall.log`

### Live Capture with Detailed Logging

```bash
sudo python3 main.py --live --interface eth0 --timeout 30
```

### View Firewall Logs

```bash
cat logs/firewall.log
```

### Run Tests

```bash
# Run all tests
pytest -v

# Run only logging tests
pytest tests/test_logging.py -v

# Run with specific verbosity
pytest tests/test_logging.py -vv
```

## Log Format

### Console and File Output

Each log entry contains:

```
2024-10-06 14:23:45 | INFO   | [2024-10-06 14:23:45] ALLOW  | 192.168.1.10:50000 -> 8.8.8.8:80 | TCP    | Rule: allow_http
```

### Structured Format Breakdown

- **Timestamp**: `[YYYY-MM-DD HH:MM:SS]`
- **Action**: `ALLOW` or `DENY`
- **Source**: `SRC_IP:SRC_PORT`
- **Destination**: `DST_IP:DST_PORT`
- **Protocol**: `TCP`, `UDP`, or `ICMP`
- **Rule**: Matched rule name and description

### Example Log Entries

```
[2024-10-06 14:23:45] ALLOW  | 192.168.1.10:50000 -> 8.8.8.8:80 | TCP    | Rule: allow_http
[2024-10-06 14:23:46] ALLOW  | 192.168.1.10:50001 -> 8.8.8.8:443 | TCP    | Rule: allow_https
[2024-10-06 14:23:47] ALLOW  | 192.168.1.50:60000 -> 10.10.10.5:22 | TCP    | Rule: allow_ssh_admin
[2024-10-06 14:23:48] DENY   | 203.0.113.9:60000 -> 10.10.10.5:22 | TCP    | Rule: DEFAULT
[2024-10-06 14:23:49] DENY   | 203.0.113.9:40000 -> 10.10.10.5:23 | TCP    | Rule: deny_telnet
[2024-10-06 14:23:50] ALLOW  | 192.168.1.10 -> 8.8.8.8 | ICMP   | Rule: allow_icmp
[2024-10-06 14:23:51] ALLOW  | 192.168.1.100:54321 -> 8.8.8.8:53 | UDP    | Rule: DEFAULT
[2024-10-06 14:23:52] DENY   | 198.51.100.100:50000 -> 10.10.10.20:8080 | TCP    | Rule: DEFAULT
```

## Log Storage

### Directory Structure

```
logs/
└── firewall.log      # Main log file (rotated)
└── firewall.log.1    # First backup (if rotated)
└── firewall.log.2    # Second backup (if rotated)
...
```

### Log Rotation

- **Max Size**: 10 MB per file
- **Backups**: 5 rotated files
- **Automatic**: No manual intervention needed

## Logging Features

### Automatic Directory Creation

The firewall automatically creates the `logs/` directory if it doesn't exist.

### Error Handling

Logging errors are caught with meaningful error messages:

```python
engine.log_error("Failed to process packet")
engine.log_warning("Unusual traffic pattern detected")
engine.log_info("Firewall started")
```

### Statistics Tracking

```python
stats = engine.get_statistics()
print(f"Total: {stats['total_packets']}")
print(f"Allowed: {stats['allowed_packets']}")
print(f"Denied: {stats['denied_packets']}")
```

## Log Entry Classes

### PacketLogRecord

Structured log entry for each packet:

```python
from firewall.logging_config import PacketLogRecord

log = PacketLogRecord(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    protocol="TCP",
    src_port=50000,
    dst_port=80,
    action="ALLOW",
    rule_name="allow_http",
    rule_description="Allow HTTP traffic"
)

# Convert to string
log_string = log.to_string()
print(log_string)

# Convert to dictionary
log_dict = log.to_dict()
print(log_dict)
```

### FirewallLogFormatter

Custom formatter for consistent log formatting:

```python
from firewall.logging_config import FirewallLogFormatter, setup_firewall_logger

logger = setup_firewall_logger()
# Logger automatically uses FirewallLogFormatter
```

## Statistics Available

```python
stats = engine.get_statistics()
# Returns: {
#     'total_packets': 8,
#     'allowed_packets': 6,
#     'denied_packets': 2
# }
```

## Error Handling

### Invalid Packets

The engine validates packets and raises errors:

```python
try:
    engine.filter_packet({})  # Missing required fields
except ValueError as e:
    print(f"Error: {e}")
```

### Missing Log Directory

The engine creates the log directory automatically:

```python
engine = FirewallEngine(log_dir="my_logs/nested/path")
# Directory is created if it doesn't exist
```

## Test Coverage

Stage 3 adds 13+ tests for logging:

- ✅ Packet log record creation
- ✅ Log record string formatting
- ✅ Log record dictionary conversion
- ✅ ICMP packet logging (no ports)
- ✅ Unknown value handling
- ✅ DENY action logging
- ✅ Logger setup and configuration
- ✅ Directory creation
- ✅ File writing
- ✅ Log format validation
- ✅ Allowed packet logging
- ✅ Denied packet logging
- ✅ Statistics tracking
- ✅ Invalid packet error handling
- ✅ Rule description in logs

## Architecture

### Logging Flow

```
1. Packet arrives at engine
2. Engine evaluates packet against rules
3. PacketLogRecord created with all details
4. Log entry formatted with consistent format
5. Written to file and console simultaneously
6. Statistics updated (ALLOW/DENY counters)
```

### Log Components

```
FirewallEngine
├── Logging Configuration
│   └── setup_firewall_logger()
├── Packet Processing
│   └── filter_packet() → logs automatically
├── Statistics
│   └── get_statistics()
└── Error Handling
    ├── log_error()
    ├── log_warning()
    └── log_info()
```

## Example Usage

### Basic Usage

```python
from firewall.engine import FirewallEngine

engine = FirewallEngine()

packet = {
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "src_port": 50000,
    "dst_port": 80,
}

decision, rule, log_msg = engine.filter_packet(packet)
print(f"Decision: {decision}")
print(f"Log: {log_msg}")
```

### With Custom Logging

```python
from firewall.engine import FirewallEngine

engine = FirewallEngine(
    log_dir="my_logs",
    log_file="custom.log"
)

engine.log_info("Firewall started")
engine.log_warning("High traffic detected")
engine.log_error("Connection refused")
```

## Integration with Previous Stages

- **Stage 1 Rules**: Fully compatible ✅
- **Stage 2 Packet Capture**: Fully integrated ✅
- **New Logging**: Transparent enhancement ✅

## What's NOT Included in Stage 3

- ❌ Database logging (file-only)
- ❌ Remote logging (syslog, etc.)
- ❌ Web dashboard
- ❌ Log analysis tools
- ❌ Real-time log streaming

## Next Stages

- **Stage 4**: VPN integration and ICMP rate limiting
- **Stage 5**: Advanced analysis and alerting
- **Stage 6**: Deployment and scaling

## File Structure

```
network-firewall/
├── firewall/
│   ├── __init__.py
│   ├── engine.py              # Updated with logging
│   ├── rules.py
│   ├── logger.py
│   ├── packet.py
│   ├── capture.py
│   ├── test_mode.py
│   └── logging_config.py      # Stage 3 (NEW)
├── config/
│   └── firewall_rules.json
├── tests/
│   ├── test_rules.py
│   ├── test_packet_parsing.py
│   └── test_logging.py        # Stage 3 (NEW)
├── logs/                      # Auto-created
│   └── firewall.log
├── main.py                    # Updated
├── requirements.txt
├── README-STAGE-1.md
├── README-STAGE-2.md
└── README-STAGE-3.md          # This file
```

## Dependencies

- Python 3.7+
- Scapy 2.5.0
- pytest >= 7.0 (for testing)

## Summary

Stage 3 completes comprehensive logging:
- Every packet logged with details ✅
- Structured log entries ✅
- Consistent formatting ✅
- Statistics tracking ✅
- Error handling ✅
- 13+ tests ✅

The firewall now provides complete visibility into all traffic decisions.
