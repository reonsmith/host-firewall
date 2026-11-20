from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class UfwRule:
    number: int
    to: str
    action: str
    direction: str
    from_: str
    comment: str


# [ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
_RULE_RE = re.compile(
    r"^\[\s*(?P<number>\d+)\]\s+"
    r"(?P<to>\S+)\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+"
    r"(?P<direction>IN|OUT|FWD)\s+"
    r"(?P<from>.+?)"
    r"(?:\s+#\s*(?P<comment>.*))?$"
)


def parse_ufw_numbered(status_text: str) -> list[UfwRule]:
    """Parse `ufw status numbered` output into rules. Skips unparseable lines."""
    rules: list[UfwRule] = []
    for raw in status_text.splitlines():
        line = raw.rstrip()
        if not line.startswith("["):
            continue
        match = _RULE_RE.match(line)
        if not match:
            continue
        comment = (match.group("comment") or "").strip()
        rules.append(
            UfwRule(
                number=int(match.group("number")),
                to=match.group("to"),
                action=match.group("action"),
                direction=match.group("direction"),
                from_=match.group("from").strip(),
                comment=comment,
            )
        )
    return rules
