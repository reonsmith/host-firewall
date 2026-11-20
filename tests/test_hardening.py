from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings, load_settings
from backend.insights import docker_published, uncovered_ports
from backend.listening import ListeningPort
from backend.ratelimit import LoginLimiter
from backend.ufw_parse import UfwRule
from backend.ufw_runner import UfwRunner
from tests.conftest import make_ss_fake, make_ufw_fake


def _settings(tmp_path: Path, **kw) -> Settings:
    ufw = tmp_path / "ufw"
    ufw.mkdir(parents=True, exist_ok=True)
    (ufw / "user.rules").write_text("rules\n", encoding="utf-8")
    base = dict(
        password="test-password-ok",
        secret_key="h" * 32,
        data_dir=tmp_path / "data",
        ufw_dir=ufw,
        ufw_bin="ufw",
        confirm_seconds=60,
        bind_host="127.0.0.1",
        bind_port=8080,
        hostname_label="hard",
        log_paths=(tmp_path / "missing.log",),
        log_limit=50,
    )
    base.update(kw)
    return Settings(**base)


def _client(tmp_path: Path, base_url: str = "http://testserver", **kw) -> TestClient:
    fake_run, _ = make_ufw_fake()
    app = create_app(
        settings=_settings(tmp_path, **kw),
        runner=UfwRunner(runner=fake_run),
        start_watchdog=False,
        listening_runner=make_ss_fake(),
    )
    return TestClient(app, base_url=base_url)


def test_limiter_locks_after_failures_and_expires():
    lim = LoginLimiter(max_failures=3, window=60, lockout=120)
    for t in (0, 1, 2):
        assert lim.retry_after("1.1.1.1", now=t) == 0
        lim.failure("1.1.1.1", now=t)
    assert lim.retry_after("1.1.1.1", now=3) > 0
    assert lim.retry_after("2.2.2.2", now=3) == 0
    assert lim.retry_after("1.1.1.1", now=200) == 0


def test_login_rate_limited_html_and_api(tmp_path: Path):
    client = _client(tmp_path)
    for _ in range(5):
        assert client.post("/login", data={"password": "wrong-password!"}).status_code == 401
    locked = client.post("/login", data={"password": "test-password-ok"})
    assert locked.status_code == 429
    assert "Too many failed attempts" in locked.text
    assert client.post("/api/login", data={"password": "test-password-ok"}).status_code == 429


def test_cookie_secure_follows_scheme(tmp_path: Path):
    http = _client(tmp_path / "a").post("/api/login", data={"password": "test-password-ok"})
    assert "secure" not in http.headers["set-cookie"].lower()
    https = _client(tmp_path / "b", base_url="https://testserver").post(
        "/api/login", data={"password": "test-password-ok"}
    )
    assert "secure" in https.headers["set-cookie"].lower()
    forced = _client(tmp_path / "c", cookie_secure=True).post(
        "/api/login", data={"password": "test-password-ok"}
    )
    assert "secure" in forced.headers["set-cookie"].lower()


def test_docker_ports_flagged_not_counted_as_uncovered():
    ports = [
        ListeningPort("tcp", "0.0.0.0:3000", "3000", "docker-proxy", "ipv4"),
        ListeningPort("tcp", "[::]:3000", "3000", "docker-proxy", "ipv6"),
        ListeningPort("tcp", "127.0.0.1:9000", "9000", "docker-proxy", "ipv4"),
        ListeningPort("tcp", "0.0.0.0:9100", "9100", "node_exporter", "ipv4"),
    ]
    rules = [UfwRule(1, "22/tcp", "ALLOW", "IN", "Anywhere", "")]
    assert [p.port for p in docker_published(ports)] == ["3000"]
    assert [p.port for p in uncovered_ports(ports, rules)] == ["9100"]


def test_demo_mode_runs_without_host_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for key in ("HOST_FIREWALL_PASSWORD", "HOST_FIREWALL_SECRET_KEY", "HOST_FIREWALL_LABEL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOST_FIREWALL_DEMO", "1")
    monkeypatch.setenv("HOST_FIREWALL_DATA_DIR", str(tmp_path / "data"))
    settings = load_settings()
    assert settings.demo and settings.hostname_label == "demo-host"
    assert settings.ufw_dir == tmp_path / "data" / "demo-ufw"
    client = TestClient(create_app(settings=settings, start_watchdog=False))
    assert "host-firewall-demo" in client.get("/login").text
    assert client.post("/login", data={"password": "host-firewall-demo"}, follow_redirects=False).status_code == 303
    page = client.get("/")
    assert page.status_code == 200
    assert "Demo mode" in page.text
    assert "docker" in page.text  # sample docker-proxy ports are flagged
    assert "Known scanner range" in page.text
    # a mutation is accepted and opens the confirm window, without touching the host
    r = client.post("/api/rules", json={"action": "allow", "port_or_app": "8443/tcp"})
    assert r.status_code == 200 and r.json()["pending"]
