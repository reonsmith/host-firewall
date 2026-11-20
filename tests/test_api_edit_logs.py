from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.ufw_runner import UfwRunner
from tests.conftest import make_ss_fake, make_ufw_fake

STATUS = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
"""

LOG_LINE = (
    "2026-11-16T13:34:13.474605+00:00 server kernel: [UFW BLOCK] IN=bond0 OUT= "
    "MAC=x SRC=89.167.77.49 DST=192.168.1.5 LEN=99 PROTO=TCP SPT=443 DPT=22 "
    "WINDOW=513 RES=0x00\n"
)


@pytest.fixture
def env(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("rules\n", encoding="utf-8")
    log = tmp_path / "ufw.log"
    log.write_text(LOG_LINE, encoding="utf-8")
    settings = Settings(
        password="test-password-ok",
        secret_key="x" * 32,
        data_dir=tmp_path / "data",
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=60,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="test-host",
        log_paths=(log,),
        log_limit=50,
    )
    fake_run, calls = make_ufw_fake(numbered=STATUS)
    app = create_app(
        settings=settings,
        runner=UfwRunner(runner=fake_run),
        start_watchdog=False,
        listening_runner=make_ss_fake(),
    )
    return TestClient(app), calls


def test_edit_deletes_then_inserts(env):
    client, calls = env
    assert client.post("/api/login", data={"password": "test-password-ok"}).status_code == 200
    r = client.put(
        "/api/rules/1",
        json={
            "action": "allow",
            "port_or_app": "22/tcp",
            "from_address": "192.168.1.0/24",
            "comment": "SSH LAN",
            "direction": "in",
        },
    )
    assert r.status_code == 200
    assert any(c[1:4] == ["--force", "delete", "1"] for c in calls)
    assert any(c[1:3] == ["insert", "1"] for c in calls)


def test_logs_endpoint(env):
    client, _ = env
    assert client.post("/api/login", data={"password": "test-password-ok"}).status_code == 200
    r = client.get("/api/logs")
    assert r.status_code == 200
    body = r.json()
    assert len(body["hits"]) == 1
    assert body["hits"][0]["action"] == "BLOCK"
    assert body["hits"][0]["src"] == "89.167.77.49"
    assert "#1" in body["hits"][0]["rule_hint"]
