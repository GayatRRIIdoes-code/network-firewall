"""Unit tests for firewall logging functionality."""

import pytest
import logging
from pathlib import Path
import tempfile
import shutil
from firewall.logging_config import (
    setup_firewall_logger,
    PacketLogRecord,
    FirewallLogFormatter,
)
from firewall.engine import FirewallEngine


class TestPacketLogRecord:
    """Test packet log record creation and formatting."""

    def test_packet_log_record_creation(self):
        """Test creating a packet log record."""
        record = PacketLogRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            action="ALLOW",
            rule_name="allow_http",
            rule_description="Allow HTTP traffic",
        )

        assert record.src_ip == "192.168.1.10"
        assert record.dst_ip == "8.8.8.8"
        assert record.protocol == "TCP"
        assert record.src_port == 50000
        assert record.dst_port == 80
        assert record.action == "ALLOW"
        assert record.rule_name == "allow_http"

    def test_packet_log_record_to_string(self):
        """Test converting log record to string format."""
        record = PacketLogRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            action="ALLOW",
            rule_name="allow_http",
        )

        log_string = record.to_string()
        
        assert "ALLOW" in log_string
        assert "192.168.1.10:50000" in log_string
        assert "8.8.8.8:80" in log_string
        assert "TCP" in log_string
        assert "allow_http" in log_string

    def test_packet_log_record_to_dict(self):
        """Test converting log record to dictionary format."""
        record = PacketLogRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            action="ALLOW",
            rule_name="allow_http",
            rule_description="Allow HTTP traffic",
        )

        log_dict = record.to_dict()
        
        assert log_dict["src_ip"] == "192.168.1.10"
        assert log_dict["dst_ip"] == "8.8.8.8"
        assert log_dict["protocol"] == "TCP"
        assert log_dict["src_port"] == 50000
        assert log_dict["dst_port"] == 80
        assert log_dict["action"] == "ALLOW"
        assert log_dict["rule_name"] == "allow_http"

    def test_packet_log_record_with_icmp(self):
        """Test log record for ICMP packets (no ports)."""
        record = PacketLogRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="ICMP",
            src_port=None,
            dst_port=None,
            action="ALLOW",
            rule_name="allow_icmp",
        )

        log_string = record.to_string()
        
        assert "192.168.1.10" in log_string
        assert "8.8.8.8" in log_string
        assert "ICMP" in log_string
        # Should not have port notation for ICMP
        assert log_string.count(":") == 1  # Only timestamp colon

    def test_packet_log_record_with_unknown_values(self):
        """Test log record with None values (unknown packets)."""
        record = PacketLogRecord(
            src_ip=None,
            dst_ip=None,
            protocol=None,
            src_port=None,
            dst_port=None,
            action="DENY",
            rule_name="DEFAULT",
        )

        assert record.src_ip == "UNKNOWN"
        assert record.dst_ip == "UNKNOWN"
        assert record.protocol == "UNKNOWN"
        
        log_string = record.to_string()
        assert "UNKNOWN" in log_string
        assert "DENY" in log_string

    def test_packet_log_record_deny_action(self):
        """Test log record for denied traffic."""
        record = PacketLogRecord(
            src_ip="203.0.113.9",
            dst_ip="10.10.10.5",
            protocol="TCP",
            src_port=40000,
            dst_port=23,
            action="DENY",
            rule_name="deny_telnet",
            rule_description="Block Telnet traffic",
        )

        log_string = record.to_string()
        
        assert "DENY" in log_string
        assert "deny_telnet" in log_string
        assert "203.0.113.9" in log_string


class TestFirewallLogger:
    """Test firewall logger setup and configuration."""

    def test_logger_setup(self):
        """Test creating a firewall logger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_firewall_logger(log_dir=tmpdir, log_file="test.log")
            
            assert logger is not None
            assert logger.name == "firewall"
            assert len(logger.handlers) > 0

    def test_logger_creates_directory(self):
        """Test that logger creates log directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "new_logs" / "nested"
            
            logger = setup_firewall_logger(log_dir=str(log_dir), log_file="test.log")
            
            assert log_dir.exists()

    def test_logger_writes_to_file(self):
        """Test that logger writes entries to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file_path = Path(tmpdir) / "test.log"
            logger = setup_firewall_logger(log_dir=tmpdir, log_file="test.log")
            
            logger.info("Test log entry")
            
            assert log_file_path.exists()
            content = log_file_path.read_text()
            assert "Test log entry" in content

    def test_logger_format(self):
        """Test log entry format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file_path = Path(tmpdir) / "test.log"
            logger = setup_firewall_logger(log_dir=tmpdir, log_file="test.log")
            
            logger.info("Format test")
            
            content = log_file_path.read_text()
            # Should contain timestamp, level, and message
            assert "|" in content
            assert "INFO" in content
            assert "Format test" in content


class TestFirewallEngineLogging:
    """Test firewall engine logging functionality."""

    def test_engine_logs_allowed_packet(self):
        """Test that engine logs allowed packets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create temp rules file
            rules_file = Path(tmpdir) / "rules.json"
            rules_file.write_text(
                '{"default_action": "DENY", "rules": ['
                '{"name": "allow_http", "action": "ALLOW", '
                '"protocol": "TCP", "dst_port": 80}]}'
            )
            
            engine = FirewallEngine(
                rules_file=str(rules_file),
                log_dir=tmpdir,
                log_file="test.log",
            )
            
            packet = {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 80,
            }
            
            decision, rule_name, log_msg = engine.filter_packet(packet)
            
            assert decision == "ALLOW"
            assert "ALLOW" in log_msg
            assert "192.168.1.10" in log_msg
            
            # Check log file
            log_file_path = Path(tmpdir) / "test.log"
            assert log_file_path.exists()

    def test_engine_logs_denied_packet(self):
        """Test that engine logs denied packets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "rules.json"
            rules_file.write_text(
                '{"default_action": "DENY", "rules": []}'
            )
            
            engine = FirewallEngine(
                rules_file=str(rules_file),
                log_dir=tmpdir,
                log_file="test.log",
            )
            
            packet = {
                "src_ip": "198.51.100.100",
                "dst_ip": "10.10.10.20",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 8080,
            }
            
            decision, rule_name, log_msg = engine.filter_packet(packet)
            
            assert decision == "DENY"
            assert "DENY" in log_msg
            assert "DEFAULT" in log_msg

    def test_engine_tracks_statistics(self):
        """Test that engine tracks packet statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "rules.json"
            rules_file.write_text(
                '{"default_action": "DENY", "rules": ['
                '{"name": "allow_http", "action": "ALLOW", '
                '"protocol": "TCP", "dst_port": 80}]}'
            )
            
            engine = FirewallEngine(
                rules_file=str(rules_file),
                log_dir=tmpdir,
            )
            
            # Process allowed packet
            engine.filter_packet({
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 80,
            })
            
            # Process denied packet
            engine.filter_packet({
                "src_ip": "198.51.100.100",
                "dst_ip": "10.10.10.20",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 8080,
            })
            
            stats = engine.get_statistics()
            
            assert stats["total_packets"] == 2
            assert stats["allowed_packets"] == 1
            assert stats["denied_packets"] == 1

    def test_engine_invalid_packet_raises_error(self):
        """Test that engine raises error for invalid packets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "rules.json"
            rules_file.write_text('{"default_action": "DENY", "rules": []}')
            
            engine = FirewallEngine(
                rules_file=str(rules_file),
                log_dir=tmpdir,
            )
            
            # Missing required fields
            with pytest.raises(ValueError):
                engine.filter_packet({"src_ip": "192.168.1.10"})
            
            # Not a dictionary
            with pytest.raises(ValueError):
                engine.filter_packet("not a dict")

    def test_engine_logging_with_rule_description(self):
        """Test that engine includes rule description in logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "rules.json"
            rules_file.write_text(
                '{"default_action": "DENY", "rules": ['
                '{"name": "allow_http", "action": "ALLOW", '
                '"protocol": "TCP", "dst_port": 80, '
                '"description": "Allow HTTP traffic on port 80"}]}'
            )
            
            engine = FirewallEngine(
                rules_file=str(rules_file),
                log_dir=tmpdir,
                log_file="test.log",
            )
            
            packet = {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 80,
            }
            
            decision, rule_name, log_msg = engine.filter_packet(packet)
            
            # Verify rule description is captured
            assert rule_name == "allow_http"
