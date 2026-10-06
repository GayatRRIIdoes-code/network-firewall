"""Live packet capture with Scapy."""

import logging
from typing import Callable, Optional
from scapy.all import sniff
from .packet import PacketProcessor
from .engine import FirewallEngine


class PacketCapture:
    """Captures live packets and processes them through the firewall."""

    def __init__(
        self,
        interface: str = "eth0",
        rules_file: str = "config/firewall_rules.json",
        packet_callback: Optional[Callable] = None,
    ):
        """Initialize packet capture.

        Args:
            interface: Network interface to sniff on (e.g., 'eth0', 'wlan0')
            rules_file: Path to firewall rules JSON file
            packet_callback: Optional callback function for each processed packet
        """
        self.interface = interface
        self.logger = logging.getLogger("firewall")
        self.engine = FirewallEngine(rules_file)
        self.processor = PacketProcessor()
        self.packet_callback = packet_callback
        self.packet_count = 0

    def _handle_packet(self, packet: Any) -> None:
        """Handle a captured packet.

        Args:
            packet: Scapy packet object
        """
        # Extract packet information
        packet_info = self.processor.process_packet(packet)
        if packet_info is None:
            return  # Skip non-IP packets

        # Filter through firewall engine
        decision, rule_name, log_msg = self.engine.filter_packet(packet_info)

        self.packet_count += 1

        # Call user-provided callback if available
        if self.packet_callback:
            self.packet_callback(packet_info, decision, rule_name)

    def start_capture(
        self,
        count: int = 0,
        timeout: Optional[float] = None,
        packet_filter: str = "",
    ) -> None:
        """Start capturing packets.

        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Timeout in seconds (None = no timeout)
            packet_filter: BPF filter string (e.g., "tcp port 80")

        Raises:
            PermissionError: If not running with root privileges
        """
        self.logger.info(
            f"Starting packet capture on interface: {self.interface}"
        )

        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                count=count,
                timeout=timeout,
                filter=packet_filter,
            )
        except PermissionError:
            self.logger.error(
                "Packet capture requires root privileges. Run with: sudo python3 main.py"
            )
            raise

        self.logger.info(
            f"Packet capture stopped. Processed {self.packet_count} packets."
        )

    def get_packet_count(self) -> int:
        """Return number of packets processed."""
        return self.packet_count
