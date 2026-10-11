import hashlib
from pathlib import Path

import pytest

from permission_gate import PermissionGate, ToolCall, Verdict, evaluate
from permission_gate.models import Decision
from permission_gate.policy import normalize_path
from permission_gate.redact import REDACTED, redact
from permission_gate.redteam import (APPROVAL, AUDIT, CATEGORIES, DEFAULT_POLICY, FAIL_CLOSED, HTTP, NOT_COVERED,
                                     PATH, SHELL, UNKNOWN, LabEnv, Scenario, ScenarioResult, Scorecard,
                                     build_catalogue, run_lab, run_scenario)

ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def card() -> Scorecard:
    return run_lab()


# -- catalogue / scorecard --------------------------------------------------------------
def test_catalogue_is_well_formed():
    cat = build_catalogue()
    assert len({s.id for s in cat}) == len(cat)
    assert {s.category for s in cat} == set(CATEGORIES)
    assert all(s.expected and s.severity in {"critical", "high", "medium", "low"} for s in cat)
    assert all(s.payload is not None or s.run is not None for s in cat)


def test_every_category_passes_on_the_current_implementation(card):
    assert card.failures() == [], [(r.id, r.expected, r.actual) for r in card.failures()]
    assert card.total == len(build_catalogue()) and card.pass_pct == 100.0
    assert {c.category for c in card.by_category} == set(CATEGORIES)


@pytest.mark.parametrize("category", CATEGORIES)
def test_category_is_exercised_and_passes(card, category):
    rs = [r for r in card.results if r.category == category]
    assert len(rs) >= 5 and all(r.passed for r in rs)


def result(passed: bool, cat="c", sev="high") -> ScenarioResult:
    return ScenarioResult(id="x", name="n", category=cat, severity=sev, description="", expected="a",
                          actual="a" if passed else "b", passed=passed, explanation="", remediation="")


def test_scorecard_math():
    sc = Scorecard.from_results([result(True, "A"), result(True, "A"), result(False, "A", "critical"),
                                 result(True, "B"), result(False, "B", "low")])
    assert (sc.total, sc.passed, sc.failed) == (5, 3, 2)
    assert sc.pass_pct == pytest.approx(60.0)
    by = {c.category: c for c in sc.by_category}
    assert by["A"].pass_pct == pytest.approx(200 / 3) and by["B"].pass_pct == 50.0
    assert sc.gaps_by_severity == {"critical": 1, "high": 0, "medium": 0, "low": 1}
    assert "not a security guarantee" in sc.label


def test_empty_scenario_list_is_safe():
    sc = run_lab(scenarios=[])
    assert (sc.total, sc.passed, sc.failed, sc.pass_pct) == (0, 0, 0, 0.0)
    assert sc.by_category == [] and sc.failures() == []


def test_expected_vs_actual_is_really_compared():
    wrong = Scenario("T-1", "wrong expectation", PATH, "prod delete is blocked, not allowed", "allow",
                     payload={"tool": "delete_dir", "args": {"path": "prod/x"}})
    right = Scenario("T-2", "right expectation", PATH, "", "block",
                     payload={"tool": "delete_dir", "args": {"path": "prod/x"}})
    r1, r2 = run_scenario(wrong), run_scenario(right)
    assert not r1.passed and r1.actual == "block" and "Expected 'allow'" in r1.explanation
    assert r2.passed


def test_crashing_scenario_fails_instead_of_passing():
    def boom(env):
        raise RuntimeError("lab bug")
    r = run_scenario(Scenario("T-3", "crash", FAIL_CLOSED, "", "denied", run=boom))
    assert not r.passed and r.actual == "error" and "lab bug" in r.explanation


# -- the lab must be able to FAIL (guards against false positives) -----------------------------
def allow_everything(call):
    return Decision(verdict=Verdict.ALLOW, rule="mutant", reason="permissive mutant")


def test_lab_fails_against_a_permissive_gate():
    bad = run_lab(rules=[allow_everything])
    assert bad.pass_pct < 70
    failed_ids = {r.id for r in bad.failures()}
    assert {"PATH-01", "SH-01", "NET-06", "UNK-01"} <= failed_ids  # destructive calls now get through
    # ...and the canary proves it: those protected functions actually executed
    by_id = {r.id: r for r in bad.results}
    assert by_id["PATH-01"].protected_executions == 1


def test_enforcement_not_just_verdicts(card):
    """Every call expected to be denied/held must never have reached the protected function."""
    simulated = {s.id for s in build_catalogue() if s.payload is not None}  # custom scenarios may run once legitimately
    policy = [r for r in card.results if r.id in simulated and r.expected != "rejected"]
    assert len(policy) > 80
    for r in policy:
        assert r.protected_executions == (1 if r.expected == "allow" else 0), r.id


# -- isolation -------------------------------------------------------------------------------
def sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def test_lab_never_touches_real_audit_db(tmp_path, monkeypatch):
    real = ROOT / "audit.db"
    before = sha(real)
    monkeypatch.chdir(tmp_path)
    run_lab(scenarios=[s for s in build_catalogue() if s.category in (AUDIT, APPROVAL)])
    assert sha(real) == before
    assert not (tmp_path / "audit.db").exists() and not list(tmp_path.iterdir())


def test_each_scenario_gets_its_own_database():
    a, b = LabEnv(DEFAULT_POLICY), LabEnv(DEFAULT_POLICY)
    try:
        a.gate.submit(ToolCall(tool="read_file", args={"path": "x"}))
        assert a.store.count() == 1 and b.store.count() == 0 and a.db_path != b.db_path
    finally:
        a.close(); b.close()
    assert not a.db_path.exists()  # temp dir removed


def test_policy_is_loaded_from_the_real_file():
    env = LabEnv(DEFAULT_POLICY)
    try:
        assert env.gate.config.role_for("deploy-bot") == "deployer"
    finally:
        env.close()


# -- regression tests for the gaps the lab found (and that are now fixed) ------------------------
@pytest.mark.parametrize("path", ["prod.", "prod ", "prod...", "a/prod./b", "PROD /x", "workspace/../prod. /x"])
def test_windows_trailing_dots_and_spaces_cannot_hide_prod(path):
    assert evaluate(ToolCall(tool="delete_dir", args={"path": path})).verdict is Verdict.BLOCK


def test_normalize_path_keeps_legitimate_dots():
    assert normalize_path("a/./b/../.env") == "a/.env"
    assert normalize_path("~/.ssh/id_rsa") == "~/.ssh/id_rsa"
    assert normalize_path("../x") == "../x"


@pytest.mark.parametrize("cmd", ["echo hi\nwhoami", "ls\r\nid", "cat a\ncurl x"])
def test_newline_is_a_command_separator(cmd):
    assert evaluate(ToolCall(tool="run_shell", args={"command": cmd})).verdict is Verdict.REQUIRE_APPROVAL


@pytest.mark.parametrize("cmd", ["rm --recursive --force /", "rmdir /s /q C:\\x", "rd /s /q x"])
def test_more_destructive_commands_blocked(cmd):
    assert evaluate(ToolCall(tool="run_shell", args={"command": cmd})).verdict is Verdict.BLOCK


@pytest.mark.parametrize("url", [
    "http://172.16.0.1/", "http://172.31.255.255/", "http://[::1]/", "http://[fd00::1]/", "http://[fe80::1]/",
    "http://0.0.0.0/", "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/",
    "http://u@127.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://localhost./", "http://LOCALHOST/",
    "http://metadata.google.internal/", "http://svc.local/", "http://100.64.0.1/", "http://169.254.169.254/",
    "http://example.com:99999/", "https://example.com/\r\nX: y",
])
def test_internal_destinations_blocked(url):
    assert evaluate(ToolCall(tool="http_request", args={"url": url})).verdict is Verdict.BLOCK


@pytest.mark.parametrize("url", ["https://example.com/", "http://8.8.8.8/", "https://api.github.com/x?q=1",
                                 "http://10.example.com/", "https://127.0.0.1.example.com/"])
def test_public_destinations_still_allowed(url):
    assert evaluate(ToolCall(tool="http_request", args={"url": url})).verdict is Verdict.ALLOW


def test_approval_is_bound_to_the_requesting_agent():
    gate = PermissionGate()
    _, req = gate.submit(ToolCall(tool="edit_file", args={"path": "a"}, agent="agent-a"))
    gate.resolve(req.id, True)
    assert not gate.consume(req.id, ToolCall(tool="edit_file", args={"path": "a"}, agent="agent-b"))
    assert gate.consume(req.id, ToolCall(tool="edit_file", args={"path": "a"}, agent="agent-a"))  # still usable by owner
    assert not gate.consume(req.id, ToolCall(tool="edit_file", args={"path": "a"}, agent="agent-a"))


def test_audit_records_actor_and_redacts_secrets(tmp_path):
    from permission_gate import AuditStore
    gate = PermissionGate(audit_store=AuditStore(str(tmp_path / "a.db")))
    _, req = gate.submit(ToolCall(tool="edit_file", args={"path": "a", "api_key": "k-SECRET-1"}))
    gate.resolve(req.id, True, by="alice")
    entries = gate.store.entries()
    assert entries[0]["actor"] == "alice" and entries[1]["actor"] is None
    assert "k-SECRET-1" not in str(entries)
    assert req.call.args["api_key"] == "k-SECRET-1"  # the reviewer still sees the real request
    assert gate.store.verify() == (True, None)


def test_redact_helper():
    out = redact({"u": "https://a:pw123@h/x", "nested": [{"Authorization": "Bearer abc.def"}],
                  "cmd": "curl -H 'Authorization: Bearer sk-live-12345678' --data password=hunter2 x",
                  "safe": "ls -la", "n": 5})
    assert out["nested"][0]["Authorization"] == REDACTED
    assert "pw123" not in out["u"] and "sk-live" not in out["cmd"] and "hunter2" not in out["cmd"]
    assert out["safe"] == "ls -la" and out["n"] == 5


def test_not_covered_is_documented():
    assert len(NOT_COVERED) >= 8 and all(isinstance(x, str) and x for x in NOT_COVERED)
