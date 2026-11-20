from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UfwLogHit:
    timestamp: str
    action: str  # BLOCK | ALLOW | AUDIT | ...
    iface_in: str
    src: str
    dst: str
    proto: str
    spt: str
    dpt: str
    raw: str

    @property
    def summary(self) -> str:
        proto = self.proto or "?"
        dpt = self.dpt or "?"
        return f"{self.action} {self.src}:{self.spt or '*'} → {self.dst}:{dpt}/{proto}"


_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+kernel:\s*\[UFW\s+(?P<action>[A-Z]+)\]\s+(?P<body>.*)$"
)
# Alternate without hostname/kernel prefix (some journal dumps)
_ALT_RE = re.compile(
    r"\[UFW\s+(?P<action>[A-Z]+)\]\s+(?P<body>.*)$"
)
_KV_RE = re.compile(r"(\w+)=(\S+)")


def parse_ufw_log_line(line: str) -> UfwLogHit | None:
    line = line.rstrip()
    if "[UFW " not in line:
        return None
    match = _LINE_RE.match(line)
    ts = ""
    action = ""
    body = ""
    if match:
        ts = match.group("ts")
        action = match.group("action")
        body = match.group("body")
    else:
        alt = _ALT_RE.search(line)
        if not alt:
            return None
        action = alt.group("action")
        body = alt.group("body")
        # Leading syslog timestamp if present
        parts = line.split(None, 1)
        if parts and parts[0][:4].isdigit() or (parts and "T" in parts[0][:20]):
            ts = parts[0]
    kv = dict(_KV_RE.findall(body))
    return UfwLogHit(
        timestamp=ts,
        action=action,
        iface_in=kv.get("IN", ""),
        src=kv.get("SRC", ""),
        dst=kv.get("DST", ""),
        proto=kv.get("PROTO", ""),
        spt=kv.get("SPT", ""),
        dpt=kv.get("DPT", ""),
        raw=line,
    )


def read_ufw_hits(
    paths: list[Path],
    *,
    limit: int = 100,
    actions: frozenset[str] | None = None,
) -> list[UfwLogHit]:
    """Read newest matching hits from log files (last lines first)."""
    if actions is None:
        actions = frozenset({"BLOCK", "ALLOW", "AUDIT"})
    hits: list[UfwLogHit] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            # Read tail without loading huge files fully
            text = _tail_text(path, max_bytes=512_000)
        except OSError:
            continue
        for line in reversed(text.splitlines()):
            hit = parse_ufw_log_line(line)
            if hit is None or hit.action not in actions:
                continue
            hits.append(hit)
            if len(hits) >= limit:
                return hits
    return hits


def _tail_text(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()  # drop partial first line
        data = fh.read()
    return data.decode("utf-8", errors="replace")


def match_rule_hint(hit: UfwLogHit, rules: list) -> str:
    """Best-effort link from a log hit to a numbered rule comment/to."""
    if not hit.dpt:
        return ""
    proto = (hit.proto or "").lower()
    for rule in rules:
        to = getattr(rule, "to", "") or ""
        # e.g. 22/tcp or 53
        if "/" in to:
            port, rproto = to.split("/", 1)
            if port == hit.dpt and (not proto or rproto.lower() == proto):
                label = getattr(rule, "comment", "") or to
                return f"#{rule.number} {label}".strip()
        elif to == hit.dpt:
            label = getattr(rule, "comment", "") or to
            return f"#{rule.number} {label}".strip()
    return ""
