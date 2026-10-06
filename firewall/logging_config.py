"""Enhanced logging configuration for firewall events."""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
from typing import Optional


class FirewallLogFormatter(logging.Formatter):
    """Custom formatter for firewall log entries."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with firewall-specific information.
        
        Args:
            record: LogRecord to format
            
        Returns:
            Formatted log string
        """
        timestamp = datetime.fromtimestamp(record.created).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return (
            f"{timestamp} | {record.levelname:<6} | {record.getMessage()}"
        )


class PacketLogRecord:
    """Structured packet log entry."""

    def __init__(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        protocol: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        action: str,
        rule_name: str,
        rule_description: Optional[str] = None,
    ):
        """Initialize a packet log entry.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: Protocol (TCP, UDP, ICMP)
            src_port: Source port
            dst_port: Destination port
            action: ALLOW or DENY
            rule_name: Name of matched rule
            rule_description: Description of matched rule
        """
        self.timestamp = datetime.now()
        self.src_ip = src_ip or "UNKNOWN"
        self.dst_ip = dst_ip or "UNKNOWN"
        self.protocol = protocol or "UNKNOWN"
        self.src_port = src_port
        self.dst_port = dst_port
        self.action = action
        self.rule_name = rule_name
        self.rule_description = rule_description or ""

    def to_string(self) -> str:
        """Convert log entry to readable string format.
        
        Returns:
            Formatted log entry
        """
        src_port_str = f":{self.src_port}" if self.src_port is not None else ""
        dst_port_str = f":{self.dst_port}" if self.dst_port is not None else ""
        
        return (
            f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{self.action:<6} | "
            f"{self.src_ip}{src_port_str} -> {self.dst_ip}{dst_port_str} | "
            f"{self.protocol:<6} | "
            f"Rule: {self.rule_name}"
        )

    def to_dict(self) -> dict:
        """Convert log entry to dictionary format.
        
        Returns:
            Dictionary representation of log entry
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "action": self.action,
            "rule_name": self.rule_name,
            "rule_description": self.rule_description,
        }


def setup_firewall_logger(
    log_dir: str = "logs",
    log_file: str = "firewall.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure and return a logger for firewall events.
    
    Args:
        log_dir: Directory to store log files
        log_file: Name of the log file
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
        
    Raises:
        OSError: If log directory cannot be created
    """
    # Create logs directory if it doesn't exist
    log_path = Path(log_dir)
    try:
        log_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create log directory {log_dir}: {e}")

    # Create logger
    logger = logging.getLogger("firewall")
    logger.setLevel(level)
    logger.propagate = False

    # Remove existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()

    # Create file handler with rotation
    log_file_path = log_path / log_file
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setLevel(level)
    except OSError as e:
        raise OSError(f"Failed to create log file {log_file_path}: {e}")

    # Create console handler for display
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    # Create formatter
    formatter = FirewallLogFormatter()
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_firewall_logger() -> logging.Logger:
    """Get the existing firewall logger or create a new one.
    
    Returns:
        Logger instance
    """
    logger = logging.getLogger("firewall")
    if not logger.handlers:
        logger = setup_firewall_logger()
    return logger
