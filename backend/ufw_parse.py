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
    family: str = "ipv4"  # ipv4 | ipv6


@dataclass(frozen=True)
class UfwStatus:
    active: bool
    logging: str  # off | on | low | medium | high | full | unknown
    default_incoming: str
    default_outgoing: str
    default_routed: str
    raw: str


# [ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
# [ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
_RULE_RE = re.compile(
    r"^\[\s*(?P<number>\d+)\]\s+"
    r"(?P<to>\S+(?:\s+\(v6\))?)\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+"
    r"(?P<direction>IN|OUT|FWD)\s+"
    r"(?P<from>.+?)"
    r"(?:\s+#\s*(?P<comment>.*))?$"
)

_STATUS_ACTIVE_RE = re.compile(r"^Status:\s*(active|inactive)\s*$", re.I | re.M)
_LOGGING_RE = re.compile(
    r"^Logging:\s*(?P<state>on|off)(?:\s*\((?P<level>[^)]+)\))?\s*$",
    re.I | re.M,
)
_DEFAULT_RE = re.compile(
    r"^Default:\s*(?P<incoming>\w+)\s*\(incoming\),\s*"
    r"(?P<outgoing>\w+)\s*\(outgoing\)(?:,\s*(?P<routed>\w+)\s*\(routed\))?",
    re.I | re.M,
)


def _detect_family(to: str, from_: str) -> str:
    blob = f"{to} {from_}".lower()
    if "(v6)" in blob or "ipv6" in blob:
        return "ipv6"
    return "ipv4"


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
        to = match.group("to").strip()
        from_ = match.group("from").strip()
        comment = (match.group("comment") or "").strip()
        rules.append(
            UfwRule(
                number=int(match.group("number")),
                to=to,
                action=match.group("action"),
                direction=match.group("direction"),
                from_=from_,
                comment=comment,
                family=_detect_family(to, from_),
            )
        )
    return rules


def parse_ufw_status(status_text: str) -> UfwStatus:
    """Parse `ufw status verbose` header fields."""
    active_m = _STATUS_ACTIVE_RE.search(status_text)
    active = bool(active_m and active_m.group(1).lower() == "active")

    logging = "unknown"
    log_m = _LOGGING_RE.search(status_text)
    if log_m:
        if log_m.group("state").lower() == "off":
            logging = "off"
        else:
            logging = (log_m.group("level") or "on").strip().lower()

    incoming = outgoing = routed = "unknown"
    def_m = _DEFAULT_RE.search(status_text)
    if def_m:
        incoming = def_m.group("incoming").lower()
        outgoing = def_m.group("outgoing").lower()
        routed = (def_m.group("routed") or "disabled").lower()

    return UfwStatus(
        active=active,
        logging=logging,
        default_incoming=incoming,
        default_outgoing=outgoing,
        default_routed=routed,
        raw=status_text,
    )


def parse_app_list(text: str) -> list[str]:
    """Parse `ufw app list` into profile names."""
    apps: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("available applications"):
            continue
        # Profiles can be space-separated on one line or one per line
        for part in re.split(r"\s{2,}|\t", line):
            name = part.strip()
            if name:
                apps.append(name)
    # Also handle single-space separated common format: "OpenSSH CUPS Apache"
    if len(apps) == 1 and " " in apps[0] and "/" not in apps[0]:
        maybe = apps[0].split()
        if all(p[:1].isupper() or p.isalnum() for p in maybe):
            return maybe
    return apps
