from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable


DEFAULT_TIMEOUT = 30


@dataclass
class AddRuleRequest:
    action: str  # allow | deny
    port_or_app: str  # e.g. 22/tcp, OpenSSH, or Anywhere / empty for host-wide
    from_address: str = "Anywhere"
    comment: str = ""
    direction: str = "in"  # in | out
    insert_at: int | None = None


class UfwRunner:
    def __init__(
        self,
        ufw_bin: str = "ufw",
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.ufw_bin = ufw_bin
        self._runner = runner or subprocess.run
        self.timeout = timeout

    def _run(self, args: list[str], *, input_text: str | None = None) -> str:
        kwargs: dict = {
            "input": input_text,
            "capture_output": True,
            "text": True,
            "check": False,
        }
        try:
            result = self._runner(
                [self.ufw_bin, *args],
                timeout=self.timeout,
                **kwargs,
            )
        except TypeError:
            result = self._runner([self.ufw_bin, *args], **kwargs)
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"ufw {' '.join(args)} failed: {err}")
        return result.stdout

    def status_numbered(self) -> str:
        return self._run(["status", "numbered"])

    def reload(self) -> str:
        return self._run(["reload"])

    def add_rule(self, req: AddRuleRequest) -> str:
        action = req.action.lower()
        if action not in {"allow", "deny"}:
            raise ValueError("action must be allow or deny")
        args: list[str] = []
        if req.insert_at is not None:
            if req.insert_at < 1:
                raise ValueError("insert_at must be >= 1")
            args.extend(["insert", str(req.insert_at)])
        args.append(action)
        if req.direction.lower() == "out":
            args.append("out")

        port = (req.port_or_app or "").strip()
        from_addr = (req.from_address or "Anywhere").strip()
        from_is_any = from_addr.lower() in {"anywhere", "any", ""}
        port_is_any = port.lower() in {"", "anywhere", "any"}

        if not from_is_any and port_is_any:
            # e.g. deny from 1.2.3.4  /  allow from 192.168.1.0/24
            args.extend(["from", from_addr])
        elif not from_is_any and not port_is_any:
            port_num, proto = _split_port_proto(port)
            args.extend(["from", from_addr, "to", "any", "port", port_num])
            if proto:
                args.extend(["proto", proto])
        else:
            # from Anywhere — port/app required unless deny/allow alone (not useful)
            if port_is_any:
                raise ValueError("port_or_app is required when From is Anywhere")
            args.append(port)

        if req.comment:
            args.extend(["comment", req.comment])
        return self._run(args)

    def delete_rule(self, number: int) -> str:
        return self._run(["--force", "delete", str(number)], input_text="y\n")


def _split_port_proto(port_or_app: str) -> tuple[str, str | None]:
    if "/" in port_or_app:
        port, proto = port_or_app.split("/", 1)
        return port, proto
    return port_or_app, None


def rule_would_block_client(
    *,
    action: str,
    from_address: str,
    client_ip: str,
) -> bool:
    """Heuristic warning: deny from Anywhere or from a network covering client."""
    if action.lower() != "deny":
        return False
    fa = from_address.strip().lower()
    if fa in {"anywhere", "any", "0.0.0.0/0", "::/0"}:
        return True
    if fa == client_ip:
        return True
    return False


def delete_might_cut_access(*, to: str, action: str, from_: str, client_ip: str) -> bool:
    """Warn when deleting an ALLOW that may be keeping management access."""
    if action.upper() != "ALLOW":
        return False
    fa = from_.strip().lower()
    covers = fa in {"anywhere", "any"} or fa == client_ip.lower() or client_ip in from_
    if not covers:
        return False
    port = to.split("/")[0].split()[0]
    return port in {"22", "80", "443", "8080", "8081"} or to.lower() in {
        "openssh",
        "ssh",
        "anywhere",
    }
