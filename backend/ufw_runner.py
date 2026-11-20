from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

from backend.ufw_parse import UfwRule, parse_ufw_numbered


DEFAULT_TIMEOUT = 30

LOGGING_LEVELS = ("off", "on", "low", "medium", "high", "full")
DEFAULT_POLICIES = ("allow", "deny", "reject")


@dataclass
class AddRuleRequest:
    action: str  # allow | deny | reject | limit
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

    def status_verbose(self) -> str:
        return self._run(["status", "verbose"])

    def reload(self) -> str:
        return self._run(["reload"])

    def enable(self) -> str:
        return self._run(["--force", "enable"])

    def disable(self) -> str:
        return self._run(["disable"])

    def set_default(self, direction: str, policy: str) -> str:
        direction = direction.lower()
        policy = policy.lower()
        if direction not in {"incoming", "outgoing", "routed"}:
            raise ValueError("direction must be incoming, outgoing, or routed")
        if policy not in DEFAULT_POLICIES:
            raise ValueError(f"policy must be one of {DEFAULT_POLICIES}")
        return self._run(["default", policy, direction])

    def set_logging(self, level: str) -> str:
        level = level.lower()
        if level not in LOGGING_LEVELS:
            raise ValueError(f"logging level must be one of {LOGGING_LEVELS}")
        return self._run(["logging", level])

    def app_list(self) -> str:
        return self._run(["app", "list"])

    def add_rule(self, req: AddRuleRequest) -> str:
        action = req.action.lower()
        if action not in {"allow", "deny", "reject", "limit"}:
            raise ValueError("action must be allow, deny, reject, or limit")
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
            args.extend(["from", from_addr])
        elif not from_is_any and not port_is_any:
            port_num, proto = _split_port_proto(port)
            args.extend(["from", from_addr, "to", "any", "port", port_num])
            if proto:
                args.extend(["proto", proto])
        else:
            if port_is_any:
                raise ValueError("port_or_app is required when From is Anywhere")
            args.append(port)

        if req.comment:
            args.extend(["comment", req.comment])
        return self._run(args)

    def delete_rule(self, number: int) -> str:
        return self._run(["--force", "delete", str(number)], input_text="y\n")

    def move_rule(self, from_number: int, to_number: int) -> str:
        """Move rule by delete + insert. Numbers are 1-based UFW indices."""
        if from_number < 1 or to_number < 1:
            raise ValueError("rule numbers must be >= 1")
        if from_number == to_number:
            return "noop"
        rules = parse_ufw_numbered(self.status_numbered())
        target = next((r for r in rules if r.number == from_number), None)
        if target is None:
            raise RuntimeError(f"Rule {from_number} not found")
        self.delete_rule(from_number)
        # After delete, insert at destination index (ufw insert places rule there)
        return self.add_rule(_rule_to_add_request(target, insert_at=to_number))


def _rule_to_add_request(rule: UfwRule, *, insert_at: int | None) -> AddRuleRequest:
    to = rule.to.replace(" (v6)", "").strip()
    from_ = rule.from_.replace(" (v6)", "").strip()
    return AddRuleRequest(
        action=rule.action.lower(),
        port_or_app=to,
        from_address=from_,
        comment=rule.comment,
        direction=rule.direction.lower(),
        insert_at=insert_at,
    )


def _split_port_proto(port_or_app: str) -> tuple[str, str | None]:
    cleaned = port_or_app.replace(" (v6)", "").strip()
    if "/" in cleaned:
        port, proto = cleaned.split("/", 1)
        return port, proto
    return cleaned, None


def rule_would_block_client(
    *,
    action: str,
    from_address: str,
    client_ip: str,
) -> bool:
    """Heuristic warning: deny from Anywhere or from a network covering client."""
    if action.lower() not in {"deny", "reject"}:
        return False
    fa = from_address.strip().lower().replace(" (v6)", "")
    if fa in {"anywhere", "any", "0.0.0.0/0", "::/0"}:
        return True
    if fa == client_ip.lower():
        return True
    return False


def delete_might_cut_access(*, to: str, action: str, from_: str, client_ip: str) -> bool:
    """Warn when deleting an ALLOW that may be keeping management access."""
    if action.upper() != "ALLOW":
        return False
    fa = from_.strip().lower().replace(" (v6)", "")
    covers = fa in {"anywhere", "any"} or fa == client_ip.lower() or client_ip in from_
    if not covers:
        return False
    port = to.split("/")[0].split()[0]
    return port in {"22", "80", "443", "8080", "8081"} or to.lower() in {
        "openssh",
        "ssh",
        "anywhere",
    }
