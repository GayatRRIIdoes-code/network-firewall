"""Enhanced firewall engine with detailed logging."""

import logging
from typing import Any, Dict, Tuple, Optional
from .rules import RuleEngine
from .logging_config import setup_firewall_logger, PacketLogRecord, get_firewall_logger


class FirewallEngine:
    """Main firewall engine that processes packets against rules with detailed logging."""

    def __init__(
        self,
        rules_file: str = "config/firewall_rules.json",
        log_dir: str = "logs",
        log_file: str = "firewall.log",
        log_level: int = logging.INFO,
    ):
        """Initialize the firewall engine.
        
        Args:
            rules_file: Path to JSON rules configuration file
            log_dir: Directory for log files
            log_file: Name of log file
            log_level: Logging level
            
        Raises:
            FileNotFoundError: If rules file not found
            OSError: If log directory cannot be created
        """
        self.rule_engine = RuleEngine(rules_file)
        self.logger = setup_firewall_logger(log_dir, log_file, log_level)
        self.packet_count = 0
        self.allowed_count = 0
        self.denied_count = 0

    def filter_packet(self, packet: Dict[str, Any]) -> Tuple[str, str, str]:
        """Filter a packet and return decision with detailed logging.
        
        Args:
            packet: Dictionary with packet info:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - protocol: TCP, UDP, ICMP, or OTHER
                - src_port: Source port (optional)
                - dst_port: Destination port (optional)
        
        Returns:
            Tuple of (decision, matched_rule, log_message)
            
        Raises:
            ValueError: If packet dictionary is invalid
        """
        # Validate packet
        if not isinstance(packet, dict):
            raise ValueError(f"Packet must be a dictionary, got {type(packet)}")

        if not packet.get("src_ip") or not packet.get("dst_ip"):
            raise ValueError(
                "Packet must contain 'src_ip' and 'dst_ip' keys"
            )

        self.packet_count += 1

        # Get matched rule from engine
        decision, rule_name = self.rule_engine.evaluate_packet(packet)

        # Get rule details for logging
        matched_rule = None
        for rule in self.rule_engine.list_rules():
            if rule.name == rule_name:
                matched_rule = rule
                break

        rule_description = matched_rule.description if matched_rule else ""

        # Create structured log entry
        log_entry = PacketLogRecord(
            src_ip=packet.get("src_ip"),
            dst_ip=packet.get("dst_ip"),
            protocol=packet.get("protocol"),
            src_port=packet.get("src_port"),
            dst_port=packet.get("dst_port"),
            action=decision,
            rule_name=rule_name,
            rule_description=rule_description,
        )

        # Update counters
        if decision == "ALLOW":
            self.allowed_count += 1
        elif decision == "DENY":
            self.denied_count += 1

        # Log the packet
        log_message = log_entry.to_string()
        self.logger.info(log_message)

        return decision, rule_name, log_message

    def get_rules(self):
        """Return list of currently loaded rules."""
        return self.rule_engine.list_rules()

    def get_statistics(self) -> Dict[str, int]:
        """Get firewall statistics.
        
        Returns:
            Dictionary with packet counts
        """
        return {
            "total_packets": self.packet_count,
            "allowed_packets": self.allowed_count,
            "denied_packets": self.denied_count,
        }

    def log_error(self, error_message: str) -> None:
        """Log an error message.
        
        Args:
            error_message: Error description
        """
        self.logger.error(error_message)

    def log_warning(self, warning_message: str) -> None:
        """Log a warning message.
        
        Args:
            warning_message: Warning description
        """
        self.logger.warning(warning_message)

    def log_info(self, info_message: str) -> None:
        """Log an info message.
        
        Args:
            info_message: Information message
        """
        self.logger.info(info_message)
