from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional


class ICMPRateLimiter:
    """Protect the firewall from excessive ICMP traffic from one source IP."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 10):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, src_ip: Optional[str]) -> bool:
        """Return True if the source is still within the configured ICMP limit."""
        if src_ip is None:
            return False

        now = time.monotonic()
        timestamps = self._history[src_ip]

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        timestamps.append(now)

        if len(timestamps) > self.max_requests:
            return False

        return True

    def reset(self, src_ip: Optional[str] = None) -> None:
        """Reset a specific source or all tracked ICMP history."""
        if src_ip is None:
            self._history.clear()
        else:
            self._history.pop(src_ip, None)


def load_icmp_settings(config: Dict[str, object]) -> ICMPRateLimiter:
    """Load ICMP rate limiting settings from a JSON configuration dictionary."""
    icmp_cfg = config.get("icmp", {})
    if not isinstance(icmp_cfg, dict):
        icmp_cfg = {}

    max_requests = int(icmp_cfg.get("max_requests", 5))
    window_seconds = int(icmp_cfg.get("window_seconds", 10))
    return ICMPRateLimiter(max_requests=max_requests, window_seconds=window_seconds)
