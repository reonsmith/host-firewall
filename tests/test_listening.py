from backend.listening import list_listening_ports, parse_ss_output


SAMPLE = """tcp   LISTEN 0      128        0.0.0.0:22       0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      128           [::]:22          [::]:*    users:(("sshd",pid=1,fd=3))
udp   UNCONN 0      0          0.0.0.0:53       0.0.0.0:*    users:(("systemd-resolve",pid=9,fd=12))
"""


def test_parse_ss_output():
    rows = parse_ss_output(SAMPLE)
    assert len(rows) == 3
    ports = {(r.proto, r.port, r.family) for r in rows}
    assert ("tcp", "22", "ipv4") in ports
    assert ("tcp", "22", "ipv6") in ports
    assert ("udp", "53", "ipv4") in ports
    ssh = next(r for r in rows if r.port == "22" and r.family == "ipv4")
    assert ssh.process == "sshd"


def test_list_listening_ports_uses_runner():
    def fake_run(args, **kwargs):
        import subprocess

        return subprocess.CompletedProcess(args, 0, stdout=SAMPLE, stderr="")

    rows = list_listening_ports(runner=fake_run)
    assert len(rows) == 3
