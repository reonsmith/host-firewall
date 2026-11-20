from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    password: str
    secret_key: str
    data_dir: Path
    ufw_dir: Path
    ufw_bin: str
    confirm_seconds: int
    bind_host: str
    bind_port: int
    hostname_label: str
    log_paths: tuple[Path, ...]
    log_limit: int


def load_settings() -> Settings:
    password = os.environ.get("HOST_FIREWALL_PASSWORD", "")
    secret = os.environ.get("HOST_FIREWALL_SECRET_KEY", "")
    if len(password) < 12:
        raise RuntimeError("HOST_FIREWALL_PASSWORD must be set (min 12 characters)")
    if len(secret) < 32:
        raise RuntimeError("HOST_FIREWALL_SECRET_KEY must be set (min 32 characters)")
    raw_logs = os.environ.get(
        "HOST_FIREWALL_LOG_PATHS",
        "/var/log/ufw.log:/var/log/kern.log:/var/log/syslog",
    )
    log_paths = tuple(Path(p) for p in raw_logs.split(":") if p.strip())
    return Settings(
        password=password,
        secret_key=secret,
        data_dir=Path(os.environ.get("HOST_FIREWALL_DATA_DIR", "/app/data")),
        ufw_dir=Path(os.environ.get("HOST_FIREWALL_UFW_DIR", "/etc/ufw")),
        ufw_bin=os.environ.get("HOST_FIREWALL_UFW_BIN", "ufw"),
        confirm_seconds=int(os.environ.get("HOST_FIREWALL_CONFIRM_SECONDS", "60")),
        bind_host=os.environ.get("HOST_FIREWALL_BIND", "0.0.0.0"),
        bind_port=int(os.environ.get("HOST_FIREWALL_PORT", "8080")),
        hostname_label=os.environ.get("HOST_FIREWALL_LABEL", "host"),
        log_paths=log_paths,
        log_limit=int(os.environ.get("HOST_FIREWALL_LOG_LIMIT", "80")),
    )
