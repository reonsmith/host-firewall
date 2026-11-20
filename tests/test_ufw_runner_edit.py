import subprocess

from backend.ufw_runner import AddRuleRequest, UfwRunner


def test_insert_allow_with_comment():
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="Rule inserted\n", stderr="")

    runner = UfwRunner(runner=fake_run)
    runner.add_rule(
        AddRuleRequest(
            action="allow",
            port_or_app="22/tcp",
            comment="SSH",
            insert_at=3,
        )
    )
    assert calls[0] == ["ufw", "insert", "3", "allow", "22/tcp", "comment", "SSH"]


def test_deny_from_ip_only():
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="ok\n", stderr="")

    runner = UfwRunner(runner=fake_run)
    runner.add_rule(
        AddRuleRequest(action="deny", port_or_app="Anywhere", from_address="1.2.3.4")
    )
    assert calls[0] == ["ufw", "deny", "from", "1.2.3.4"]
