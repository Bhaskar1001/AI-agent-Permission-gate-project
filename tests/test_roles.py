from pathlib import Path

import pytest

from permission_gate import PermissionGate, PolicyConfig, ToolCall, Verdict, load_policy

POLICY = Path(__file__).parent.parent / "policy.yaml"


@pytest.fixture(scope="module")
def gate():
    return PermissionGate(config=load_policy(POLICY))


def verdict(gate, agent, tool, **args):
    return gate.decide(ToolCall(tool=tool, agent=agent, args=args)).verdict


def test_role_mapping():
    cfg = load_policy(POLICY)
    assert cfg.role_for("reader-7") == "reader"
    assert cfg.role_for("deploy-bot") == "deployer"
    assert cfg.role_for("someone") == "default"


def test_reader_is_tool_restricted(gate):
    assert verdict(gate, "reader-1", "read_file", path="a.py") is Verdict.ALLOW
    assert verdict(gate, "reader-1", "edit_file", path="a.py") is Verdict.BLOCK
    assert verdict(gate, "reader-1", "run_shell", command="ls") is Verdict.BLOCK
    assert verdict(gate, "other", "edit_file", path="a.py") is Verdict.REQUIRE_APPROVAL


def test_deployer_relaxes_workspace_edits(gate):
    assert verdict(gate, "deploy-bot", "edit_file", path="workspace/app.py") is Verdict.ALLOW
    assert verdict(gate, "deploy-bot", "edit_file", path="src/app.py") is Verdict.REQUIRE_APPROVAL
    # other agents don't get the relaxation
    assert verdict(gate, "other", "edit_file", path="workspace/app.py") is Verdict.REQUIRE_APPROVAL


def test_relaxation_cannot_defeat_builtin_protection(gate):
    # traversal normalises to prod/..., so neither the glob nor the relax applies
    assert verdict(gate, "deploy-bot", "edit_file", path="workspace/../prod/x") is Verdict.REQUIRE_APPROVAL
    assert verdict(gate, "deploy-bot", "delete_dir", path="workspace/prod") is Verdict.BLOCK
    assert verdict(gate, "deploy-bot", "write_file", path="workspace/.env") is Verdict.BLOCK


def test_roles_can_tighten(gate):
    assert verdict(gate, "deploy-bot", "delete_file", path="db/migrations/001.sql") is Verdict.BLOCK
    assert verdict(gate, "deploy-bot", "run_shell", command="pip install x") is Verdict.BLOCK
    assert verdict(gate, "other", "run_shell", command="pip install x") is Verdict.REQUIRE_APPROVAL


def test_decision_reports_role_rule(gate):
    d = gate.decide(ToolCall(tool="edit_file", agent="deploy-bot", args={"path": "workspace/a"}))
    assert d.rule == "role:deployer:workspace-edits-preapproved"


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        PolicyConfig(agents={"x": "ghost"})
