from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ListeningPort:
    proto: str
    local: str
    port: str
    process: str
    family: str  # ipv4 | ipv6


def parse_ss_output(text: str) -> list[ListeningPort]:
    """Parse `ss -H -tulpn` lines into listening sockets."""
    rows: list[ListeningPort] = []
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        # Netid State Recv-Q Send-Q Local Peer [Process...]
        state = parts[1].upper()
        if state not in {"LISTEN", "UNCONN"}:
            continue
        local = parts[4]
        process = ""
        rest = " ".join(parts[6:]) if len(parts) > 6 else ""
        m = re.search(r'"([^"]+)"', rest)
        if m:
            process = m.group(1)
        port, family = _split_local(local)
        key = (proto, local)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            ListeningPort(
                proto=proto,
                local=local,
                port=port,
                process=process,
                family=family,
            )
        )
    rows.sort(key=lambda r: (r.proto, int(r.port) if r.port.isdigit() else 0, r.local))
    return rows


def _split_local(local: str) -> tuple[str, str]:
    if local.startswith("["):
        m = re.match(r"^\[(?P<addr>[^\]]+)\]:(?P<port>\d+)$", local)
        if m:
            return m.group("port"), "ipv6"
    if ":" in local:
        host, port = local.rsplit(":", 1)
        if port.isdigit():
            return port, ("ipv6" if ":" in host else "ipv4")
    return local, "ipv4"


def list_listening_ports(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    timeout: int = 10,
) -> list[ListeningPort]:
    run = runner or subprocess.run
    try:
        result = run(
            ["ss", "-H", "-tulpn"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except TypeError:
        result = run(["ss", "-H", "-tulpn"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return []
    if getattr(result, "returncode", 1) != 0:
        return []
    return parse_ss_output(result.stdout or "")
