from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class PendingConflictError(RuntimeError):
    pass


class PendingExpiredError(RuntimeError):
    pass


class NoPendingError(RuntimeError):
    pass


@dataclass
class PendingChange:
    snapshot_path: str
    description: str
    client_ip: str
    created_at: float
    expires_at: float
    warn_blocks_client: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def seconds_remaining(self, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        return max(0.0, self.expires_at - now)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["seconds_remaining"] = self.seconds_remaining()
        d["expired"] = self.is_expired()
        return d


class PendingStore:
    def __init__(self, data_dir: Path, ttl_seconds: int = 60) -> None:
        self.data_dir = data_dir
        self.ttl_seconds = ttl_seconds
        self._path = data_dir / "pending.json"
        self._lock = threading.RLock()
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def get(self) -> PendingChange | None:
        with self._lock:
            return self._read()

    def start(
        self,
        *,
        snapshot_path: Path,
        description: str,
        client_ip: str,
        warn_blocks_client: bool = False,
        now: float | None = None,
    ) -> PendingChange:
        now = now if now is not None else time.time()
        with self._lock:
            existing = self._read()
            if existing is not None:
                # Include expired: must restore+clear before a new change
                raise PendingConflictError(
                    "A pending change already exists (confirm, roll back, or wait for auto-rollback)"
                )
            change = PendingChange(
                snapshot_path=str(snapshot_path),
                description=description,
                client_ip=client_ip,
                created_at=now,
                expires_at=now + self.ttl_seconds,
                warn_blocks_client=warn_blocks_client,
            )
            self._write(change)
            return change

    def confirm(self, now: float | None = None) -> PendingChange:
        now = now if now is not None else time.time()
        with self._lock:
            change = self._read()
            if change is None:
                raise NoPendingError("No pending change")
            if change.is_expired(now):
                raise PendingExpiredError(
                    "Pending change expired; already rolled back or needs rollback"
                )
            self._clear()
            return change

    def peek_expired(self, now: float | None = None) -> PendingChange | None:
        now = now if now is not None else time.time()
        with self._lock:
            change = self._read()
            if change is None or not change.is_expired(now):
                return None
            return change

    def clear_if_snapshot(self, snapshot_path: str) -> bool:
        """Clear pending only if it still points at this snapshot. Returns True if cleared."""
        with self._lock:
            change = self._read()
            if change is None:
                return False
            if change.snapshot_path != snapshot_path:
                return False
            self._clear()
            return True

    def rollback(self) -> PendingChange:
        """Peek pending for manual rollback; does not clear until clear_if_snapshot."""
        with self._lock:
            change = self._read()
            if change is None:
                raise NoPendingError("No pending change")
            return change

    def is_expired(self, now: float | None = None) -> bool:
        change = self.get()
        if change is None:
            return False
        return change.is_expired(now)

    def _read(self) -> PendingChange | None:
        if not self._path.exists():
            return None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return PendingChange(**raw)

    def _write(self, change: PendingChange) -> None:
        self._path.write_text(json.dumps(asdict(change)), encoding="utf-8")

    def _clear(self) -> None:
        if self._path.exists():
            self._path.unlink()
