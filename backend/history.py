from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class HistoryEntry:
    ts: float
    description: str
    client_ip: str
    outcome: str  # confirmed | rolled_back
    snapshot_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
        return d


class ChangeHistory:
    def __init__(self, data_dir: Path, *, max_entries: int = 200) -> None:
        self.path = data_dir / "history.jsonl"
        self.max_entries = max_entries
        data_dir.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        description: str,
        client_ip: str,
        outcome: str,
        snapshot_path: str = "",
        ts: float | None = None,
    ) -> HistoryEntry:
        entry = HistoryEntry(
            ts=ts if ts is not None else time.time(),
            description=description,
            client_ip=client_ip,
            outcome=outcome,
            snapshot_path=snapshot_path,
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")
        self._trim()
        return entry

    def recent(self, limit: int = 50) -> list[HistoryEntry]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        entries: list[HistoryEntry] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            entries.append(HistoryEntry(**raw))
        entries.reverse()
        return entries

    def _trim(self) -> None:
        if not self.path.exists():
            return
        lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if len(lines) <= self.max_entries:
            return
        self.path.write_text("\n".join(lines[-self.max_entries :]) + "\n", encoding="utf-8")
