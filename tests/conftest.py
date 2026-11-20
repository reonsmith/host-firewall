from __future__ import annotations

import subprocess
from pathlib import Path

NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH
[ 3] 80/tcp                     ALLOW IN    Anywhere
"""

VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

APPS = """Available applications:
  OpenSSH
  Nginx Full
"""


def make_ufw_fake(calls: list | None = None, *, numbered: str = NUMBERED):
    calls = calls if calls is not None else []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        cmd = args[1:]
        if cmd[:2] == ["status", "numbered"]:
            return subprocess.CompletedProcess(args, 0, stdout=numbered, stderr="")
        if cmd[:2] == ["status", "verbose"]:
            return subprocess.CompletedProcess(args, 0, stdout=VERBOSE, stderr="")
        if cmd[:2] == ["app", "list"]:
            return subprocess.CompletedProcess(args, 0, stdout=APPS, stderr="")
        if cmd[:1] == ["reload"] or cmd == ["--force", "enable"] or cmd == ["disable"]:
            return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")
        if cmd[:1] == ["default"] or cmd[:1] == ["logging"]:
            return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")
        if cmd[:1] == ["allow"] or cmd[:1] == ["deny"] or cmd[:1] == ["reject"] or cmd[:1] == ["limit"]:
            return subprocess.CompletedProcess(args, 0, stdout="Rule added\n", stderr="")
        if cmd[:2] == ["insert", ] or (len(cmd) >= 2 and cmd[0] == "insert"):
            return subprocess.CompletedProcess(args, 0, stdout="Rule inserted\n", stderr="")
        if cmd[:2] == ["--force", "delete"] or (len(cmd) >= 3 and cmd[0] == "--force" and cmd[1] == "delete"):
            return subprocess.CompletedProcess(args, 0, stdout="Deleted\n", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    return fake_run, calls


def make_ss_fake(text: str = ""):
    sample = text or (
        "tcp   LISTEN 0      128        0.0.0.0:22       0.0.0.0:*    users:((\"sshd\",pid=1,fd=3))\n"
        "tcp   LISTEN 0      128           [::]:22          [::]:*    users:((\"sshd\",pid=1,fd=3))\n"
        "tcp   LISTEN 0      128        0.0.0.0:80       0.0.0.0:*    users:((\"nginx\",pid=2,fd=6))\n"
    )

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=sample, stderr="")

    return fake_run


def seed_ufw_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "user.rules").write_text("# test\n", encoding="utf-8")
