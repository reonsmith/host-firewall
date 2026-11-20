"""In-memory failed-login limiter, keyed by client IP."""

from __future__ import annotations

import threading
import time


class LoginLimiter:
    """Lock an IP out for `lockout` seconds after `max_failures` failures within `window`."""

    def __init__(self, *, max_failures: int = 5, window: float = 300, lockout: float = 300) -> None:
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, ip: str, *, now: float | None = None) -> int:
        """Seconds until this IP may try again; 0 if allowed now."""
        now = now if now is not None else time.monotonic()
        with self._lock:
            until = self._locked_until.get(ip, 0)
            if until > now:
                return int(until - now) + 1
            self._locked_until.pop(ip, None)
            return 0

    def failure(self, ip: str, *, now: float | None = None) -> None:
        now = now if now is not None else time.monotonic()
        with self._lock:
            recent = [t for t in self._fails.get(ip, []) if now - t < self.window]
            recent.append(now)
            if len(recent) >= self.max_failures:
                self._locked_until[ip] = now + self.lockout
                recent = []
            self._fails[ip] = recent
            # keep memory bounded
            if len(self._fails) > 10_000:
                self._fails.clear()

    def success(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)
            self._locked_until.pop(ip, None)
