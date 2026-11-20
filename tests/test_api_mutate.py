import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.ufw_runner import UfwRunner


STATUS = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
"""


@pytest.fixture
def env(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("rules\n", encoding="utf-8")
    data = tmp_path / "data"
    settings = Settings(
        password="test-password-ok",
        secret_key="x" * 32,
        data_dir=data,
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=60,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="test-host",
        log_paths=(tmp_path / "missing.log",),
        log_limit=50,
    )

    def fake_run(args, **kwargs):
        cmd = args[1:]
        if cmd[:2] == ["status", "numbered"]:
            out = STATUS
        else:
            out = "ok\n"
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    app = create_app(
        settings=settings,
        runner=UfwRunner(runner=fake_run),
        start_watchdog=False,
    )
    client = TestClient(app)
    return client, settings


def _login(client: TestClient) -> None:
    r = client.post("/api/login", data={"password": "test-password-ok"})
    assert r.status_code == 200


def test_add_creates_pending_and_second_blocked(env):
    client, _ = env
    _login(client)
    r = client.post(
        "/api/rules",
        json={
            "action": "allow",
            "port_or_app": "9999/tcp",
            "from_address": "Anywhere",
            "comment": "temp test",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pending"]["description"].endswith("# temp test")
    assert "temp test" in body["pending"]["description"]

    r2 = client.post(
        "/api/rules",
        json={"action": "allow", "port_or_app": "9998/tcp"},
    )
    assert r2.status_code == 409


def test_confirm_keeps_change(env):
    client, settings = env
    _login(client)
    client.post(
        "/api/rules",
        json={"action": "allow", "port_or_app": "9999/tcp", "comment": "keep"},
    )
    r = client.post("/api/pending/confirm")
    assert r.status_code == 200
    assert client.get("/api/pending").json()["pending"] is None
    # snapshot files still exist under data
    assert any(settings.data_dir.joinpath("snapshots").iterdir())


def test_rollback_restores_files(env):
    client, settings = env
    _login(client)
    (settings.ufw_dir / "user.rules").write_text("BEFORE\n", encoding="utf-8")
    client.post(
        "/api/rules",
        json={"action": "allow", "port_or_app": "9999/tcp"},
    )
    # Simulate mutation side effect on files
    (settings.ufw_dir / "user.rules").write_text("AFTER\n", encoding="utf-8")
    r = client.post("/api/pending/rollback")
    assert r.status_code == 200
    assert (settings.ufw_dir / "user.rules").read_text(encoding="utf-8") == "BEFORE\n"


def test_confirm_after_expiry_errors(env):
    import json
    import time

    client, _ = env
    _login(client)
    client.post(
        "/api/rules",
        json={"action": "allow", "port_or_app": "9999/tcp"},
    )
    store = client.app.state.pending
    raw = json.loads(store._path.read_text(encoding="utf-8"))
    raw["expires_at"] = time.time() - 1
    store._path.write_text(json.dumps(raw), encoding="utf-8")

    r = client.post("/api/pending/confirm")
    assert r.status_code == 409
