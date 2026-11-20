import subprocess
import time
from pathlib import Path

from backend.app import create_app
from backend.config import Settings
from backend.ufw_runner import UfwRunner
from fastapi.testclient import TestClient


def test_watchdog_rolls_back_without_http(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("BEFORE\n", encoding="utf-8")
    settings = Settings(
        password="test-password-ok",
        secret_key="z" * 32,
        data_dir=tmp_path / "data",
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=1,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="wd",
        log_paths=(tmp_path / "missing.log",),
        log_limit=50,
    )

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")

    app = create_app(
        settings=settings,
        runner=UfwRunner(runner=fake_run),
        start_watchdog=True,
    )
    with TestClient(app) as client:
        assert client.post("/api/login", data={"password": "test-password-ok"}).status_code == 200
        r = client.post(
            "/api/rules",
            json={"action": "allow", "port_or_app": "9999/tcp", "comment": "wd"},
        )
        assert r.status_code == 200
        (ufw / "user.rules").write_text("AFTER\n", encoding="utf-8")
        deadline = time.time() + 5
        while time.time() < deadline:
            if (ufw / "user.rules").read_text(encoding="utf-8") == "BEFORE\n":
                break
            time.sleep(0.2)
        assert (ufw / "user.rules").read_text(encoding="utf-8") == "BEFORE\n"
        assert client.get("/api/pending").json()["pending"] is None
