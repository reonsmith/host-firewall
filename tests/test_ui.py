from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.ufw_runner import UfwRunner
from tests.conftest import make_ss_fake, make_ufw_fake


@pytest.fixture
def client(tmp_path: Path):
    ufw = tmp_path / "ufw"
    ufw.mkdir()
    (ufw / "user.rules").write_text("rules\n", encoding="utf-8")
    settings = Settings(
        password="test-password-ok",
        secret_key="y" * 32,
        data_dir=tmp_path / "data",
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=60,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="ui-host",
        log_paths=(tmp_path / "missing.log",),
        log_limit=50,
    )
    fake_run, _ = make_ufw_fake()
    app = create_app(
        settings=settings,
        runner=UfwRunner(runner=fake_run),
        start_watchdog=False,
        listening_runner=make_ss_fake(),
    )
    return TestClient(app)


def test_login_and_dashboard_shows_comment(client: TestClient):
    unauth = client.get("/", follow_redirects=False)
    assert unauth.status_code in (303, 307)
    bad = client.post("/login", data={"password": "wrong-password"}, follow_redirects=False)
    assert bad.status_code == 401
    ok = client.post("/login", data={"password": "test-password-ok"}, follow_redirects=False)
    assert ok.status_code == 303
    page = client.get("/")
    assert page.status_code == 200
    assert "SSH" in page.text
    assert "Add rule" in page.text
    assert "Active" in page.text
    assert "Listening ports" in page.text
    assert "ipv6" in page.text
    assert "Change history" in page.text
    assert 'id="rule-list"' in page.text
    assert "Drag rows" in page.text
    assert "/static/app.js" in page.text
    assert "Blocked traffic" in page.text
    assert "Open ports with no rule" in page.text
    assert 'draggable="true"' in page.text
    assert 'http-equiv="refresh"' not in page.text.replace("<noscript><meta http-equiv=\"refresh\"", "")
