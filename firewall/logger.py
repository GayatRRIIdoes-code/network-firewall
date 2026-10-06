"""Logging configuration for firewall events."""

import logging
from pathlib import Path
from datetime import datetime


def setup_logger(log_dir: str = "logs", log_file: str = "firewall.log") -> logging.Logger:
    """Configure and return a logger for firewall events.
    
    Args:
        log_dir: Directory to store log files
        log_file: Name of the log file
    
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger("firewall")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Remove existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()

    # Create file handler
    file_handler = logging.FileHandler(log_path / log_file)
    file_handler.setLevel(logging.INFO)

    # Create console handler for display
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
