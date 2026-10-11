import json
import sqlite3

from fastapi.testclient import TestClient

from permission_gate import AuditStore, PermissionGate, ToolCall
from permission_gate.api import create_app


def test_chain_verifies_and_persists(tmp_path):
    db = tmp_path / "a.db"
    gate = PermissionGate(audit_store=AuditStore(str(db)))
    gate.submit(ToolCall(tool="read_file", args={"path": "a"}))
    gate.submit(ToolCall(tool="delete_dir", args={"path": "prod"}))
    _, req = gate.submit(ToolCall(tool="edit_file", args={"path": "a"}))
    gate.resolve(req.id, True)

    reopened = AuditStore(str(db))  # survives restarts
    assert reopened.count() == 4 and reopened.verify() == (True, None)
    assert [e["final"] for e in reopened.entries()] == ["approved", "pending", "blocked", "allowed"]
    assert [e["final"] for e in reopened.entries(final="blocked")] == ["blocked"]


def test_tampering_detected(tmp_path):
    db = tmp_path / "a.db"
    store = AuditStore(str(db))
    gate = PermissionGate(audit_store=store)
    for p in ("a", "prod", "b"):
        gate.submit(ToolCall(tool="delete_dir", args={"path": p}))
    assert store.verify()[0]

    raw = sqlite3.connect(db)
    # rewrite history: pretend the prod delete was merely allowed
    payload = json.loads(raw.execute("SELECT payload FROM audit WHERE id=2").fetchone()[0])
    payload["final"] = "allowed"
    raw.execute("UPDATE audit SET payload=? WHERE id=2", (json.dumps(payload),))
    raw.commit()
    assert AuditStore(str(db)).verify() == (False, 2)


def test_deleted_row_detected(tmp_path):
    db = tmp_path / "a.db"
    gate = PermissionGate(audit_store=AuditStore(str(db)))
    for p in ("a", "b", "c"):
        gate.submit(ToolCall(tool="read_file", args={"path": p}))
    raw = sqlite3.connect(db)
    raw.execute("DELETE FROM audit WHERE id=2")
    raw.commit()
    assert AuditStore(str(db)).verify() == (False, 3)


def make_client(**kw):
    gate = PermissionGate(audit_store=AuditStore())
    return TestClient(create_app(gate, **kw)), gate


def test_api_flow():
    c, _ = make_client()
    r = c.post("/v1/check", json={"tool": "read_file", "args": {"path": "a"}}).json()
    assert r["verdict"] == "allow" and r["request_id"] is None
    r = c.post("/v1/check", json={"tool": "delete_dir", "args": {"path": "prod"}}).json()
    assert r["verdict"] == "block"

    r = c.post("/v1/check", json={"tool": "edit_file", "args": {"path": "a"}, "agent": "bot"}).json()
    rid = r["request_id"]
    assert r["verdict"] == "require_approval"
    assert c.get(f"/v1/requests/{rid}").json()["status"] == "pending"
    assert [x["id"] for x in c.get("/v1/requests").json()] == [rid]

    call = {"tool": "edit_file", "args": {"path": "a"}, "agent": "bot"}
    assert c.post(f"/v1/requests/{rid}/consume", json=call).status_code == 409  # not approved
    assert c.post(f"/v1/requests/{rid}/approve", json={"by": "alice"}).json()["status"] == "approved"
    assert c.post(f"/v1/requests/{rid}/approve").status_code == 409
    assert c.post(f"/v1/requests/{rid}/consume", json=call).status_code == 200
    assert c.post(f"/v1/requests/{rid}/consume", json=call).status_code == 409  # single use

    assert c.get("/v1/requests/nope").status_code == 404
    assert c.post("/v1/requests/nope/approve").status_code == 404
    assert len(c.get("/v1/audit", params={"verdict": "block"}).json()) == 1
    v = c.get("/v1/audit/verify").json()
    assert v["ok"] and v["entries"] == 5  # allowed, blocked, pending, approved, executed


def test_api_auth_separates_agent_and_reviewer():
    c, _ = make_client(agent_key="AK", reviewer_key="RK")
    body = {"tool": "edit_file", "args": {"path": "a"}}
    assert c.post("/v1/check", json=body).status_code == 401
    assert c.post("/v1/check", json=body, headers={"X-API-Key": "bad"}).status_code == 401
    r = c.post("/v1/check", json=body, headers={"X-API-Key": "AK"})
    assert r.status_code == 200
    rid = r.json()["request_id"]
    # an agent must not be able to approve its own request
    assert c.post(f"/v1/requests/{rid}/approve", headers={"X-API-Key": "AK"}).status_code == 401
    assert c.get("/v1/audit", headers={"X-API-Key": "AK"}).status_code == 401
    assert c.post(f"/v1/requests/{rid}/approve", headers={"X-API-Key": "RK"}).status_code == 200


def test_api_rejects_invalid_body():
    c, _ = make_client()
    assert c.post("/v1/check", json={"args": {}}).status_code == 422
