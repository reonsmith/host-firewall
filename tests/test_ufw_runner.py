import subprocess

from backend.ufw_runner import AddRuleRequest, UfwRunner, rule_would_block_client


def test_add_rule_includes_comment():
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="Rule added\n", stderr="")

    runner = UfwRunner(ufw_bin="ufw", runner=fake_run)
    runner.add_rule(AddRuleRequest(action="allow", port_or_app="22/tcp", comment="SSH"))
    assert calls[0] == ["ufw", "allow", "22/tcp", "comment", "SSH"]


def test_delete_rule_force():
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="Deleted\n", stderr="")

    runner = UfwRunner(runner=fake_run)
    runner.delete_rule(3)
    assert calls[0] == ["ufw", "--force", "delete", "3"]


def test_rule_would_block_client_heuristic():
    assert rule_would_block_client(action="deny", from_address="Anywhere", client_ip="1.2.3.4")
    assert not rule_would_block_client(action="allow", from_address="Anywhere", client_ip="1.2.3.4")
    assert rule_would_block_client(action="deny", from_address="1.2.3.4", client_ip="1.2.3.4")
    assert rule_would_block_client(action="reject", from_address="Anywhere", client_ip="1.2.3.4")
