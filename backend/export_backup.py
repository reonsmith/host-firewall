from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path


def build_ufw_export_tar(
    ufw_dir: Path,
    *,
    status_numbered: str = "",
    status_verbose: str = "",
) -> bytes:
    """Create a tar.gz of /etc/ufw plus status dumps for download."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        if ufw_dir.is_dir():
            for path in sorted(ufw_dir.rglob("*")):
                if path.is_file():
                    arcname = f"ufw/{path.relative_to(ufw_dir).as_posix()}"
                    tar.add(path, arcname=arcname)
        if status_numbered:
            _add_text(tar, "status-numbered.txt", status_numbered)
        if status_verbose:
            _add_text(tar, "status-verbose.txt", status_verbose)
        _add_text(
            tar,
            "README.txt",
            "Host Firewall UFW export\n"
            f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            "Restore by copying the ufw/ tree back to /etc/ufw and running ufw reload,\n"
            "or use the panel Restore from snapshot after uploading is not supported —\n"
            "use a local snapshot under data/snapshots via the UI.\n",
        )
    return buf.getvalue()


def list_snapshots(data_dir: Path) -> list[dict]:
    root = data_dir / "snapshots"
    if not root.is_dir():
        return []
    rows: list[dict] = []
    for path in sorted(root.iterdir(), reverse=True):
        if path.is_dir() and path.name.startswith("ufw-"):
            rows.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "mtime": path.stat().st_mtime,
                }
            )
    return rows


def _add_text(tar: tarfile.TarFile, name: str, content: str) -> None:
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))
