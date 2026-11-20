from __future__ import annotations

import shutil
import time
from pathlib import Path


def create_snapshot(ufw_dir: Path, data_dir: Path) -> Path:
    """Copy /etc/ufw tree into data_dir/snapshots/<ts> and return that path."""
    if not ufw_dir.is_dir():
        raise FileNotFoundError(f"UFW directory missing: {ufw_dir}")
    snap_root = data_dir / "snapshots"
    snap_root.mkdir(parents=True, exist_ok=True)
    dest = snap_root / f"ufw-{int(time.time())}"
    if dest.exists():
        dest = snap_root / f"ufw-{int(time.time() * 1000)}"
    shutil.copytree(ufw_dir, dest)
    return dest


def restore_snapshot(snapshot_path: Path, ufw_dir: Path) -> None:
    """Replace ufw_dir contents with snapshot_path contents."""
    if not snapshot_path.is_dir():
        raise FileNotFoundError(f"Snapshot missing: {snapshot_path}")
    ufw_dir.mkdir(parents=True, exist_ok=True)
    for child in ufw_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in snapshot_path.iterdir():
        target = ufw_dir / child.name
        if child.is_dir():
            shutil.copytree(child, target)
        else:
            shutil.copy2(child, target)
