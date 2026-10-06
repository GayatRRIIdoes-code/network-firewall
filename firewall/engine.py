"""Firewall engine for packet filtering."""

import logging
from typing import Any, Dict, Tuple
from .rules import RuleEngine
from .logger import setup_logger


class FirewallEngine:
    """Main firewall engine that processes packets against rules."""

    def __init__(self, rules_file: str = "config/firewall_rules.json"):
        """Initialize the firewall engine.
        
        Args:
            rules_file: Path to JSON rules configuration file
        """
        self.rule_engine = RuleEngine(rules_file)
        self.logger = setup_logger()

    def filter_packet(self, packet: Dict[str, Any]) -> Tuple[str, str, str]:
        """Filter a packet and return decision with logged information.
        
        Args:
            packet: Dictionary with packet info:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - protocol: TCP, UDP, ICMP, or OTHER
                - src_port: Source port (optional)
                - dst_port: Destination port (optional)
        
        Returns:
            Tuple of (decision, matched_rule, log_message)
        """
        # Evaluate packet against rules
        decision, rule_name = self.rule_engine.evaluate_packet(packet)

        # Build log message
        log_message = (
            f"Decision: {decision} | "
            f"Rule: {rule_name} | "
            f"Src: {packet.get('src_ip', 'UNKNOWN')}:{packet.get('src_port', 'N/A')} | "
            f"Dst: {packet.get('dst_ip', 'UNKNOWN')}:{packet.get('dst_port', 'N/A')} | "
            f"Protocol: {packet.get('protocol', 'UNKNOWN')}"
        )

        # Log the decision
        self.logger.info(log_message)

        return decision, rule_name, log_message

    def get_rules(self):
        """Return list of currently loaded rules."""
        return self.rule_engine.list_rules()
