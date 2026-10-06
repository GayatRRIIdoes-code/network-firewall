"""Unit tests for firewall rule matching."""

import pytest
from firewall.rules import FirewallRule, RuleEngine


class TestFirewallRule:
    """Test individual firewall rule matching."""

    def test_rule_exact_port_match(self):
        """Test matching a specific destination port."""
        rule = FirewallRule(
            name="http_rule",
            action="ALLOW",
            protocol="TCP",
            dst_port=80,
        )
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
        }
        assert rule.matches(packet) is True

    def test_rule_port_mismatch(self):
        """Test that rule does not match incorrect port."""
        rule = FirewallRule(
            name="http_rule",
            action="ALLOW",
            protocol="TCP",
            dst_port=80,
        )
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 443,  # Wrong port
        }
        assert rule.matches(packet) is False

    def test_rule_protocol_match(self):
        """Test matching protocol."""
        rule = FirewallRule(
            name="ssh_rule",
            action="ALLOW",
            protocol="TCP",
            dst_port=22,
        )
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 22,
        }
        assert rule.matches(packet) is True

    def test_rule_protocol_mismatch(self):
        """Test that rule does not match incorrect protocol."""
        rule = FirewallRule(
            name="ssh_rule",
            action="ALLOW",
            protocol="TCP",
            dst_port=22,
        )
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.10.10.5",
            "protocol": "UDP",  # Wrong protocol
            "src_port": 60000,
            "dst_port": 22,
        }
        assert rule.matches(packet) is False

    def test_rule_exact_ip_match(self):
        """Test matching exact source IP."""
        rule = FirewallRule(
            name="admin_ssh",
            action="ALLOW",
            protocol="TCP",
            src_ip="192.168.1.50",
            dst_port=22,
        )
        packet = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 22,
        }
        assert rule.matches(packet) is True

    def test_rule_ip_mismatch(self):
        """Test that rule does not match incorrect source IP."""
        rule = FirewallRule(
            name="admin_ssh",
            action="ALLOW",
            protocol="TCP",
            src_ip="192.168.1.50",
            dst_port=22,
        )
        packet = {
            "src_ip": "203.0.113.9",  # Wrong IP
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 22,
        }
        assert rule.matches(packet) is False

    def test_rule_cidr_network_match(self):
        """Test matching IP CIDR range."""
        rule = FirewallRule(
            name="internal_network",
            action="ALLOW",
            protocol="ANY",
            src_ip="192.168.0.0/16",
        )
        packet = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
        }
        assert rule.matches(packet) is True

    def test_rule_cidr_network_mismatch(self):
        """Test that rule does not match IP outside CIDR range."""
        rule = FirewallRule(
            name="internal_network",
            action="ALLOW",
            protocol="ANY",
            src_ip="192.168.0.0/16",
        )
        packet = {
            "src_ip": "10.0.0.1",  # Outside range
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
        }
        assert rule.matches(packet) is False

    def test_rule_any_protocol(self):
        """Test rule with ANY protocol matches all protocols."""
        rule = FirewallRule(
            name="any_protocol",
            action="ALLOW",
            protocol="ANY",
            dst_port=53,
        )
        for protocol in ["TCP", "UDP", "ICMP"]:
            packet = {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": protocol,
                "src_port": 50000,
                "dst_port": 53,
            }
            assert rule.matches(packet) is True

    def test_rule_icmp(self):
        """Test ICMP rule matching."""
        rule = FirewallRule(
            name="allow_icmp",
            action="ALLOW",
            protocol="ICMP",
        )
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "ICMP",
        }
        assert rule.matches(packet) is True


class TestRuleEngine:
    """Test the rule engine evaluation logic."""

    def test_engine_allow_http(self):
        """Test that HTTP traffic is allowed."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "ALLOW"
        assert rule_name == "allow_http"

    def test_engine_allow_https(self):
        """Test that HTTPS traffic is allowed."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 50001,
            "dst_port": 443,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "ALLOW"
        assert rule_name == "allow_https"

    def test_engine_allow_ssh_from_admin(self):
        """Test that SSH is allowed from authorized admin IP."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 22,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "ALLOW"
        assert rule_name == "allow_ssh_admin"

    def test_engine_deny_ssh_from_unauthorized(self):
        """Test that SSH from unauthorized IP is denied."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "203.0.113.9",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 60000,
            "dst_port": 22,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "DENY"

    def test_engine_deny_telnet(self):
        """Test that Telnet traffic is blocked."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "203.0.113.9",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 40000,
            "dst_port": 23,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "DENY"
        assert rule_name == "deny_telnet"

    def test_engine_allow_icmp(self):
        """Test that ICMP traffic is allowed."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "ICMP",
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "ALLOW"
        assert rule_name == "allow_icmp"

    def test_engine_default_deny(self):
        """Test that unmatched traffic is denied by default."""
        engine = RuleEngine("config/firewall_rules.json")
        packet = {
            "src_ip": "198.51.100.100",
            "dst_ip": "10.10.10.20",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 8080,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "DENY"
        assert rule_name == "DEFAULT"

    def test_engine_rule_order_matters(self):
        """Test that first matching rule is used."""
        engine = RuleEngine("config/firewall_rules.json")
        # Telnet should match deny_telnet before any general rule
        packet = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.10.10.5",
            "protocol": "TCP",
            "src_port": 40000,
            "dst_port": 23,
        }
        decision, rule_name = engine.evaluate_packet(packet)
        assert decision == "DENY"
        assert rule_name == "deny_telnet"
