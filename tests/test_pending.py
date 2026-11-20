from pathlib import Path

import pytest

from backend.pending import PendingConflictError, PendingExpiredError, PendingStore


def test_single_pending_and_ttl(tmp_path: Path):
    store = PendingStore(tmp_path, ttl_seconds=60)
    first = store.start(
        snapshot_path=tmp_path / "snap1",
        description="add 9999",
        client_ip="192.168.1.10",
        now=1000.0,
    )
    assert first.expires_at == 1060.0
    assert store.get() is not None

    with pytest.raises(PendingConflictError):
        store.start(
            snapshot_path=tmp_path / "snap2",
            description="other",
            client_ip="192.168.1.10",
            now=1010.0,
        )

    with pytest.raises(PendingExpiredError):
        store.confirm(now=1070.0)

    expired = store.peek_expired(now=1070.0)
    assert expired is not None
    # Expired still blocks a new start until cleared after restore
    with pytest.raises(PendingConflictError):
        store.start(
            snapshot_path=tmp_path / "snap3",
            description="retry",
            client_ip="192.168.1.10",
            now=2000.0,
        )

    assert store.clear_if_snapshot(expired.snapshot_path) is True
    again = store.start(
        snapshot_path=tmp_path / "snap3",
        description="retry",
        client_ip="192.168.1.10",
        now=2000.0,
    )
    confirmed = store.confirm(now=2010.0)
    assert confirmed.description == "retry"
    assert store.get() is None
    assert again.snapshot_path.endswith("snap3")
