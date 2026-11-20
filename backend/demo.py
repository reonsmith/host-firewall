"""Demo mode: fake UFW, ss and logs so the panel can be explored safely.

Enabled with HOST_FIREWALL_DEMO=1. Nothing on the host is read or changed:
UFW commands are answered from canned output, mutations "succeed" without
effect, and sample log lines are generated into the data directory.
"""

from __future__ import annotations

import json
import random
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.ufw_runner import UfwRunner

DEMO_PASSWORD = "host-firewall-demo"

NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     LIMIT IN    10.0.10.0/24               # SSH from management VLAN
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # Reverse proxy HTTP (redirects to HTTPS)
[ 3] 443/tcp                    ALLOW IN    Anywhere                   # Reverse proxy HTTPS for the dashboard, Git and media apps
[ 4] 8080/tcp                   ALLOW IN    10.0.10.0/24               # Host Firewall panel
[ 5] Anywhere                   DENY IN     203.0.113.0/24             # Known scanner range
[ 6] 53                         ALLOW IN    10.0.10.0/24               # Local DNS resolver
[ 7] 22/tcp (v6)                LIMIT IN    Anywhere (v6)              # SSH
[ 8] 443/tcp (v6)               ALLOW IN    Anywhere (v6)
"""

VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
"""

APPS = """Available applications:
  OpenSSH
  Nginx Full
  Nginx HTTPS
"""

SS = (
    'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))\n'
    'tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))\n'
    'tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=1204,fd=7))\n'
    'tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("python",pid=2210,fd=6))\n'
    'tcp LISTEN 0 4096 0.0.0.0:9100 0.0.0.0:* users:(("node_exporter",pid=990,fd=3))\n'
    'tcp LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:* users:(("docker-proxy",pid=3302,fd=4))\n'
    'tcp LISTEN 0 4096 0.0.0.0:8096 0.0.0.0:* users:(("docker-proxy",pid=3390,fd=4))\n'
    'tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=1501,fd=5))\n'
    'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=640,fd=4))\n'
)


def _fake_ufw(args, **_kwargs):
    cmd = list(args[1:])
    if cmd[:2] == ["status", "numbered"]:
        out = NUMBERED
    elif cmd[:2] == ["status", "verbose"]:
        out = VERBOSE + "\n" + NUMBERED.split("\n", 1)[1]
    elif cmd[:2] == ["app", "list"]:
        out = APPS
    else:
        out = "ok (demo: no change made)\n"
    return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")


def _fake_ss(args, **_kwargs):
    return subprocess.CompletedProcess(args, 0, stdout=SS, stderr="")


def write_sample_log(path: Path, *, seed: int = 11, hours: int = 24) -> None:
    """Generate believable UFW BLOCK lines for the last `hours` hours."""
    rnd = random.Random(seed)
    now = datetime.now(timezone.utc)
    lines: list[tuple[datetime, str]] = []
    ports = [23, 445, 3389, 5900, 6379, 8443, 2375, 1433]
    prefixes = ["198.51.100", "203.0.113", "192.0.2", "100.64.12"]
    for h in range(hours, 0, -1):
        base = 6 + int(14 * abs((h % 12) - 6) / 6)
        count = base + (55 if h == 6 else 0) + rnd.randint(0, 8)
        for _ in range(count):
            t = now - timedelta(hours=h - 1, minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59))
            src = f"{rnd.choice(prefixes)}.{rnd.randint(2, 254)}"
            lines.append((t, (
                f"{t.isoformat(timespec='microseconds')} demo-host kernel: [UFW BLOCK] IN=eth0 OUT= "
                f"SRC={src} DST=10.0.10.8 LEN=44 PROTO=TCP SPT={rnd.randint(1024, 65000)} "
                f"DPT={rnd.choice(ports)} WINDOW=1024 SYN"
            )))
    lines.sort()
    path.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")


def _seed_history(data_dir: Path) -> None:
    hist = data_dir / "history.jsonl"
    if hist.exists():
        return
    now = time.time()
    entries = [
        (now - 86400 * 2, "add allow 53 from 10.0.10.0/24 (Local DNS resolver)", "confirmed"),
        (now - 3600 * 7, "insert deny from 203.0.113.0/24 at 5", "confirmed"),
        (now - 3600 * 3, "move rule 6 → 4", "rolled_back"),
        (now - 60 * 12, "edit #3 → allow 443/tcp from Anywhere", "confirmed"),
    ]
    with hist.open("w", encoding="utf-8") as fh:
        for ts, desc, outcome in entries:
            fh.write(json.dumps({
                "ts": ts, "description": desc, "client_ip": "10.0.10.20",
                "outcome": outcome, "snapshot_path": "",
            }) + "\n")


def prepare_demo(data_dir: Path, ufw_dir: Path, log_path: Path):
    """Create demo files and return (ufw runner, listening runner)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    ufw_dir.mkdir(parents=True, exist_ok=True)
    rules = ufw_dir / "user.rules"
    if not rules.exists():
        rules.write_text("# demo\n", encoding="utf-8")
    write_sample_log(log_path)
    _seed_history(data_dir)
    return UfwRunner(runner=_fake_ufw), _fake_ss
