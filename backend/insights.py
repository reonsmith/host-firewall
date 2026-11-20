"""Derived dashboard figures: hourly block chart, uncovered ports, KPI summary."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

from backend.ufw_logs import UfwLogHit

_LOOPBACK_PREFIXES = ("127.", "[::1]", "::1", "localhost")


def parse_log_timestamp(ts: str) -> datetime | None:
    """Parse an ISO-8601 syslog timestamp (rsyslog high-precision format)."""
    if not ts or not ts[:4].isdigit():
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # treat naive as container-local
    return dt


def hourly_blocks(
    hits: Iterable[UfwLogHit],
    *,
    now: datetime | None = None,
    hours: int = 24,
    action: str = "BLOCK",
) -> dict:
    """Bucket hits of one action into the last `hours` hourly bins.

    The same kernel line often appears in ufw.log, kern.log and syslog, so hits
    are de-duplicated on their raw text first.
    """
    now = now or datetime.now(timezone.utc)
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    start = end - timedelta(hours=hours)
    counts = [0] * hours
    seen: set[str] = set()
    display_tz = None
    unparsed = 0
    for hit in hits:
        if hit.action != action or hit.raw in seen:
            continue
        seen.add(hit.raw)
        dt = parse_log_timestamp(hit.timestamp)
        if dt is None:
            unparsed += 1
            continue
        if display_tz is None:
            display_tz = dt.tzinfo
        if start <= dt < end:
            counts[int((dt - start) // timedelta(hours=1))] += 1
    tz = display_tz or timezone.utc
    peak = max(counts) if counts else 0
    peak_index = counts.index(peak) if peak else -1
    bars = []
    for i, count in enumerate(counts):
        bucket_start = (start + timedelta(hours=i)).astimezone(tz)
        bars.append(
            {
                "label": bucket_start.strftime("%H"),
                "title": bucket_start.strftime("%H:00"),
                "count": count,
                "pct": round(count / peak * 100, 1) if peak else 0,
                "is_peak": i == peak_index,
            }
        )
    return {
        "bars": bars,
        "total": sum(counts),
        "peak": peak,
        "unparsed": unparsed,
    }


def _is_loopback(local: str) -> bool:
    return local.startswith(_LOOPBACK_PREFIXES)


def _covered_ports(rules) -> tuple[set[str], list[tuple[int, int]]]:
    singles: set[str] = set()
    ranges: list[tuple[int, int]] = []
    for rule in rules:
        if str(getattr(rule, "action", "")).upper() not in {"ALLOW", "LIMIT"}:
            continue
        to = (getattr(rule, "to", "") or "").replace("(v6)", "").strip()
        port_part = to.split("/", 1)[0]
        for chunk in port_part.split(","):
            if ":" in chunk:
                lo, _, hi = chunk.partition(":")
                if lo.isdigit() and hi.isdigit():
                    ranges.append((int(lo), int(hi)))
            elif chunk.isdigit():
                singles.add(chunk)
    return singles, ranges


def uncovered_ports(ports, rules) -> list:
    """Non-loopback listening ports with no allow/limit rule naming that port.

    App-profile rules (e.g. "OpenSSH") can't be mapped to ports here, so a port
    covered only by an app profile is still reported.
    """
    singles, ranges = _covered_ports(rules)
    out = []
    seen: set[tuple[str, str]] = set()
    for p in ports:
        if not p.port.isdigit() or _is_loopback(p.local):
            continue
        key = (p.proto, p.port)
        if key in seen:
            continue
        if p.port in singles or any(lo <= int(p.port) <= hi for lo, hi in ranges):
            continue
        seen.add(key)
        out.append(p)
    return out


def relative_time(ts: float, *, now: float | None = None) -> str:
    delta = max(0, int((now or time.time()) - ts))
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{delta // 60} min ago"
    if delta < 86400:
        return f"{delta // 3600} h ago"
    return f"{delta // 86400} d ago"
