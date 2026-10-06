from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class VPNManager:
    """Track VPN interfaces and protected address ranges for firewall checks."""

    def __init__(
        self,
        config_path: str = "config/wg0.conf",
        interface_names: Optional[Iterable[str]] = None,
        networks: Optional[Iterable[str]] = None,
    ):
        self.config_path = Path(config_path)
        self.interface_names = list(interface_names or ["wg0", "tun0"])
        self.networks = list(networks or [])
        self._load_config()

    def _load_config(self) -> None:
        """Load VPN config from a WireGuard-style file if it exists."""
        if not self.config_path.exists():
            return

        for raw_line in self.config_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("address") or line.lower().startswith("allowedips"):
                _, value = line.split("=", 1)
                value = value.strip()
                if value:
                    for part in value.split(","):
                        item = part.strip()
                        if "/" in item:
                            self.networks.append(item)

    def is_vpn_interface(self, interface_name: Optional[str]) -> bool:
        """Return True if a name looks like a VPN interface."""
        if interface_name is None:
            return False

        lowered = interface_name.lower()
        return lowered in {name.lower() for name in self.interface_names} or lowered.startswith(("wg", "tun"))

    def is_vpn_packet(self, packet: Dict[str, Any], interface_name: Optional[str] = None) -> bool:
        """Return True if the packet appears to come from VPN traffic."""
        if self.is_vpn_interface(interface_name):
            return True

        packet_interface = packet.get("interface")
        if self.is_vpn_interface(packet_interface):
            return True

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        if not src_ip or not dst_ip:
            return False

        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
        except ValueError:
            return False

        for network in self.networks:
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError:
                continue

            if src_obj in net or dst_obj in net:
                return True

        return False

    def example_config_text(self) -> str:
        """Return a safe example WireGuard configuration for a lab environment."""
        return """[Interface]
Address = 10.50.0.1/24
ListenPort = 51820
PrivateKey = <replace-with-private-key>

[Peer]
PublicKey = <replace-with-public-key>
AllowedIPs = 10.50.0.0/24
"""
