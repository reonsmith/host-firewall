from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.export_backup import build_ufw_export_tar
from backend.history import ChangeHistory
from backend.ufw_runner import UfwRunner
from tests.conftest import make_ss_fake, make_ufw_fake


@pytest.fixture
def env(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("rules\n", encoding="utf-8")
    settings = Settings(
        password="test-password-ok",
        secret_key="x" * 32,
        data_dir=tmp_path / "data",
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=60,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="feat",
        log_paths=(tmp_path / "missing.log",),
        log_limit=50,
    )
    fake_run, calls = make_ufw_fake()
    app = create_app(
        settings=settings,
        runner=UfwRunner(runner=fake_run),
        start_watchdog=False,
        listening_runner=make_ss_fake(),
    )
    return TestClient(app), settings, calls


def _login(client: TestClient) -> None:
    assert client.post("/api/login", data={"password": "test-password-ok"}).status_code == 200


def test_status_endpoint(env):
    client, _, _ = env
    _login(client)
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["logging"] == "low"
    assert body["default_incoming"] == "deny"


def test_move_rule(env):
    client, _, calls = env
    _login(client)
    r = client.post("/api/rules/3/move", json={"to_number": 1})
    assert r.status_code == 200
    assert any(c[1:4] == ["--force", "delete", "3"] for c in calls)
    assert any(c[1:3] == ["insert", "1"] for c in calls)


def test_enable_disable_logging_default(env):
    client, _, calls = env
    _login(client)
    assert client.post("/api/ufw/enable").status_code == 200
    assert client.post("/api/pending/confirm").status_code == 200
    assert client.post("/api/ufw/disable").status_code == 200
    assert client.post("/api/pending/rollback").status_code == 200
    assert client.post("/api/ufw/logging", json={"level": "medium"}).status_code == 200
    assert client.post("/api/pending/confirm").status_code == 200
    assert (
        client.post(
            "/api/ufw/default", json={"direction": "incoming", "policy": "deny"}
        ).status_code
        == 200
    )
    assert any(c[1:3] == ["logging", "medium"] for c in calls)
    assert any(c[1:4] == ["default", "deny", "incoming"] for c in calls)


def test_ports_and_apps(env):
    client, _, _ = env
    _login(client)
    ports = client.get("/api/ports").json()["ports"]
    assert any(p["port"] == "22" for p in ports)
    apps = client.get("/api/apps").json()["apps"]
    assert "OpenSSH" in apps


def test_export_download(env):
    client, _, _ = env
    _login(client)
    r = client.get("/api/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/gzip")
    assert r.content[:2] == b"\x1f\x8b"


def test_restore_snapshot(env):
    client, settings, _ = env
    _login(client)
    # Create a snapshot via mutation
    client.post("/api/rules", json={"action": "allow", "port_or_app": "9999/tcp"})
    client.post("/api/pending/confirm")
    snaps = client.get("/api/snapshots").json()["snapshots"]
    assert snaps
    name = snaps[0]["name"]
    (settings.ufw_dir / "user.rules").write_text("CHANGED\n", encoding="utf-8")
    r = client.post("/api/snapshots/restore", json={"snapshot_name": name})
    assert r.status_code == 200
    assert (settings.ufw_dir / "user.rules").read_text(encoding="utf-8") == "rules\n"


def test_export_helper_and_history(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("x\n", encoding="utf-8")
    blob = build_ufw_export_tar(ufw, status_numbered="Status: active\n")
    assert blob[:2] == b"\x1f\x8b"
    hist = ChangeHistory(tmp_path / "data")
    hist.append(description="test", client_ip="1.2.3.4", outcome="confirmed")
    rows = hist.recent()
    assert rows[0].description == "test"


def test_ufw_runner_move_and_policy():
    import subprocess

    from backend.ufw_runner import UfwRunner

    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[1:3] == ["status", "numbered"]:
            out = (
                "Status: active\n"
                "[ 1] 22/tcp ALLOW IN Anywhere # SSH\n"
                "[ 2] 80/tcp ALLOW IN Anywhere\n"
            )
        else:
            out = "ok\n"
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    runner = UfwRunner(runner=fake_run)
    runner.move_rule(2, 1)
    assert ["ufw", "--force", "delete", "2"] in calls
    assert any(c[1:3] == ["insert", "1"] for c in calls)
    runner.set_logging("high")
    runner.set_default("outgoing", "allow")
    runner.enable()
    runner.disable()
