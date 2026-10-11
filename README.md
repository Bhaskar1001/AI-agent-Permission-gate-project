# AI Agent Permission Gate

A safety layer that decides whether an AI agent's proposed tool call is **allowed**, **blocked**, or **sent for human approval**.

| Proposed call | Verdict |
|---|---|
| `read_file src/main.py` | 🟢 allow |
| `edit_file src/main.py` | 🟡 needs approval |
| `delete_dir /var/www/production` | 🔴 block |

## Run

```bash
pip install -r requirements.txt
pytest                                   # 99 tests (incl. red-team lab)
streamlit run app.py                     # interactive UI (uses policy.yaml + audit.db)
uvicorn permission_gate.api:app          # REST API (see env vars in permission_gate/api.py)
```

## Use in your agent

**Decorator (simplest):**

```python
from permission_gate import PermissionGate, AuditStore, load_policy, gated_tool, ApprovalRequired

gate = PermissionGate(config=load_policy("policy.yaml"), audit_store=AuditStore("audit.db"))

@gated_tool(gate, agent="deploy-bot")           # wait=60 to block until a human decides
def edit_file(path, content): ...

edit_file("workspace/a.py", "...")              # allowed by the deployer role
try:
    edit_file("src/a.py", "...")
except ApprovalRequired as e:                   # PermissionDenied if blocked
    ...  # after a human approves: edit_file("src/a.py", "...", _approval_id=e.request.id)
```

An approval is **single use** and only valid for the exact call that was approved.

**REST API** (any language): `POST /v1/check` returns `allow` / `block` / `require_approval` (+ `request_id`);
poll `GET /v1/requests/{id}`; reviewers use `/approve`, `/reject`, `/v1/audit`, `/v1/audit/verify`.
Set `PERMISSION_GATE_AGENT_KEY` and `PERMISSION_GATE_REVIEWER_KEY` so agents can't approve their own requests.
If the gate is unreachable or errors, the client must treat the call as **denied**.

## How it works

- `permission_gate/models.py` – Pydantic models (`ToolCall`, `Decision`, `ApprovalRequest`, `AuditEntry`).
- `permission_gate/policy.py` – independent rules per tool family; **strictest verdict wins**; unknown tools are **default-deny**.
  Paths are normalised (`..`, `\`, drive letters, case) so `tmp/../prod` can't dodge the production check.
  Shell commands are screened for dangerous patterns, and only a short safe list without chaining (`;`, `|`, `&`, `>`) is auto-allowed. HTTP requests block internal addresses (SSRF).
- `permission_gate/gate.py` – `PermissionGate`: evaluates, queues approvals, records a JSONL audit trail.
- `permission_gate/policy_config.py` + `policy.yaml` – per-agent roles. Roles can tighten freely; they can only relax a plain "needs approval" to allow, never a block or a prod/sensitive path.
- `permission_gate/guard.py` – `@gated_tool` decorator (sync + async, optional wait for approval).
- `permission_gate/api.py` – FastAPI service with separate agent / reviewer keys.
- `permission_gate/audit_store.py` – SQLite audit log with a SHA-256 hash chain; edited or deleted rows are detected by `verify()`. Anchor `head()` externally to also catch tail truncation.
- `app.py` – Streamlit UI: submit calls, approve/reject queue, audit table.

## Red-Team Lab

`permission_gate/redteam.py` runs 117 simulated attacks (path traversal, shell chaining, unknown tools,
approval abuse, SSRF, fail-closed behaviour, audit tampering) against the **real** policy and gate. Each scenario gets a
temporary audit DB, nothing is executed, and no network request is made. Policy scenarios drive a canary function through
`@gated_tool`, so the lab checks that denied calls never reach the protected code, not just the verdict.

```bash
pytest tests/test_redteam.py             # lab + regression tests
streamlit run app.py                     # scroll to "Red-Team Lab" and click Run Security Tests
python -c "from permission_gate.redteam import run_lab; c = run_lab(); print(c.passed, '/', c.total)"
```

The output is a **scenario-based test score, not a security guarantee**. `redteam.NOT_COVERED` lists what the lab does not test.

## Limits

This is a pattern-based policy, a first line of defence, not a sandbox. Run agent tools with least privilege too. Add or change rules in `policy.py` (each rule is a function `ToolCall -> Decision | None`).
