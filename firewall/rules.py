"""Firewall rules loading and matching."""

import json
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional


class FirewallRule:
    """Represents a single firewall rule."""

    def __init__(
        self,
        name: str,
        action: str,
        protocol: str = "ANY",
        src_ip: str = "ANY",
        dst_ip: str = "ANY",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        description: str = "",
    ):
        """Initialize a firewall rule.
        
        Args:
            name: Unique rule identifier
            action: ALLOW or DENY
            protocol: TCP, UDP, ICMP, or ANY
            src_ip: Source IP or CIDR or ANY
            dst_ip: Destination IP or CIDR or ANY
            src_port: Source port number or None
            dst_port: Destination port number or None
            description: Human-readable rule description
        """
        self.name = name
        self.action = action.upper()
        self.protocol = protocol.upper()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.description = description

    def matches(self, packet: Dict[str, Any]) -> bool:
        """Check if a packet matches this rule.
        
        Args:
            packet: Dict with keys: src_ip, dst_ip, protocol, src_port, dst_port
        
        Returns:
            True if packet matches all rule conditions, False otherwise
        """
        # Check protocol
        if self.protocol != "ANY":
            if packet.get("protocol", "UNKNOWN").upper() != self.protocol:
                return False

        # Check source IP
        if self.src_ip != "ANY":
            if not self._ip_matches(self.src_ip, packet.get("src_ip")):
                return False

        # Check destination IP
        if self.dst_ip != "ANY":
            if not self._ip_matches(self.dst_ip, packet.get("dst_ip")):
                return False

        # Check source port
        if self.src_port is not None:
            if packet.get("src_port") != self.src_port:
                return False

        # Check destination port
        if self.dst_port is not None:
            if packet.get("dst_port") != self.dst_port:
                return False

        return True

    @staticmethod
    def _ip_matches(rule_ip: str, packet_ip: Optional[str]) -> bool:
        """Check if packet IP matches rule IP (supports CIDR).
        
        Args:
            rule_ip: IP address, CIDR network, or wildcard
            packet_ip: IP address from packet
        
        Returns:
            True if IPs match, False otherwise
        """
        if packet_ip is None:
            return False

        try:
            # Handle CIDR notation (e.g., 192.168.1.0/24)
            if "/" in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            # Handle exact IP match
            else:
                return ipaddress.ip_address(packet_ip) == ipaddress.ip_address(rule_ip)
        except ValueError:
            return False

    def __repr__(self) -> str:
        return f"FirewallRule(name={self.name}, action={self.action}, protocol={self.protocol})"


class RuleEngine:
    """Manages firewall rules and packet evaluation."""

    def __init__(self, rules_file: str = "config/firewall_rules.json"):
        """Initialize the rule engine.
        
        Args:
            rules_file: Path to JSON configuration file
        """
        self.rules: List[FirewallRule] = []
        self.default_action = "DENY"
        self.load_rules(rules_file)

    def load_rules(self, rules_file: str) -> None:
        """Load firewall rules from JSON file.
        
        Args:
            rules_file: Path to JSON configuration file
        
        Raises:
            FileNotFoundError: If rules file does not exist
            json.JSONDecodeError: If JSON is invalid
        """
        config_path = Path(rules_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Rules file not found: {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in {rules_file}", e.doc, e.pos)

        # Load default action if specified
        self.default_action = config.get("default_action", "DENY").upper()

        # Load all rules
        self.rules = []
        for rule_data in config.get("rules", []):
            rule = FirewallRule(
                name=rule_data.get("name", "unnamed"),
                action=rule_data.get("action", "DENY"),
                protocol=rule_data.get("protocol", "ANY"),
                src_ip=rule_data.get("src_ip", "ANY"),
                dst_ip=rule_data.get("dst_ip", "ANY"),
                src_port=rule_data.get("src_port"),
                dst_port=rule_data.get("dst_port"),
                description=rule_data.get("description", ""),
            )
            self.rules.append(rule)

    def evaluate_packet(self, packet: Dict[str, Any]) -> tuple[str, str]:
        """Evaluate a packet against all rules in order.
        
        Args:
            packet: Dict with keys: src_ip, dst_ip, protocol, src_port, dst_port
        
        Returns:
            Tuple of (decision, rule_name) where decision is ALLOW or DENY
        """
        for rule in self.rules:
            if rule.matches(packet):
                return (rule.action, rule.name)

        # No rule matched, use default
        return (self.default_action, "DEFAULT")

    def list_rules(self) -> List[FirewallRule]:
        """Return list of all loaded rules."""
        return self.rules
