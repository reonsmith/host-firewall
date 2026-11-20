from datetime import datetime, timezone

from backend.insights import hourly_blocks, parse_log_timestamp, relative_time, uncovered_ports
from backend.listening import ListeningPort
from backend.ufw_logs import UfwLogHit
from backend.ufw_parse import UfwRule


def _hit(ts: str, action: str = "BLOCK", raw: str | None = None) -> UfwLogHit:
    return UfwLogHit(
        timestamp=ts, action=action, iface_in="eth0", src="1.2.3.4", dst="10.0.0.8",
        proto="TCP", spt="5555", dpt="23", raw=raw or f"{ts} host kernel: [UFW {action}] x",
    )


def test_parse_iso_and_reject_bsd_syslog():
    assert parse_log_timestamp("2026-11-20T13:05:01.123456+02:00") is not None
    assert parse_log_timestamp("Nov") is None
    assert parse_log_timestamp("") is None


def test_hourly_blocks_buckets_and_dedupes():
    now = datetime(2026, 11, 20, 13, 30, tzinfo=timezone.utc)
    hits = [
        _hit("2026-11-20T13:10:00+00:00"),
        _hit("2026-11-20T13:10:00+00:00"),  # same raw line from kern.log: deduped
        _hit("2026-11-20T13:20:00+00:00"),
        _hit("2026-11-20T12:59:59+00:00"),
        _hit("2026-11-20T13:15:00+00:00", action="ALLOW"),  # not a block
        _hit("2026-11-18T09:00:00+00:00"),  # outside window
        _hit("Nov"),  # unparseable timestamp
    ]
    chart = hourly_blocks(hits, now=now)
    assert len(chart["bars"]) == 24
    assert chart["bars"][-1]["count"] == 2
    assert chart["bars"][-2]["count"] == 1
    assert chart["total"] == 3
    assert chart["peak"] == 2
    assert chart["bars"][-1]["is_peak"]
    assert chart["bars"][-1]["label"] == "13"
    assert chart["unparsed"] == 1


def test_hourly_blocks_empty():
    chart = hourly_blocks([], now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    assert chart["total"] == 0 and chart["peak"] == 0
    assert not any(b["is_peak"] for b in chart["bars"])


def test_uncovered_ports_ignores_loopback_ranges_and_deny():
    rules = [
        UfwRule(1, "22/tcp", "ALLOW", "IN", "Anywhere", "SSH"),
        UfwRule(2, "6000:6010/tcp", "ALLOW", "IN", "Anywhere", ""),
        UfwRule(3, "8081", "DENY", "IN", "Anywhere", ""),
    ]
    ports = [
        ListeningPort("tcp", "0.0.0.0:22", "22", "sshd", "ipv4"),
        ListeningPort("tcp", "0.0.0.0:6005", "6005", "x", "ipv4"),
        ListeningPort("tcp", "127.0.0.1:5432", "5432", "postgres", "ipv4"),
        ListeningPort("tcp", "[::1]:631", "631", "cups", "ipv6"),
        ListeningPort("tcp", "0.0.0.0:8081", "8081", "app", "ipv4"),
        ListeningPort("tcp", "[::]:8081", "8081", "app", "ipv6"),
    ]
    out = uncovered_ports(ports, rules)
    assert [(p.proto, p.port) for p in out] == [("tcp", "8081")]


def test_relative_time():
    assert relative_time(100, now=130) == "just now"
    assert relative_time(0, now=600) == "10 min ago"
    assert relative_time(0, now=7200) == "2 h ago"
    assert relative_time(0, now=3 * 86400) == "3 d ago"
