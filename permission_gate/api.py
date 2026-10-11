"""FastAPI service so agents in any language can call the gate.

Run:  uvicorn permission_gate.api:app
Env:  PERMISSION_GATE_POLICY (yaml path), PERMISSION_GATE_DB (sqlite path),
      PERMISSION_GATE_AGENT_KEY / PERMISSION_GATE_REVIEWER_KEY (X-API-Key; unset = open, dev only)

Fail closed: if /v1/check errors or is unreachable, the client must treat the call as denied.
"""
from __future__ import annotations

import hmac
import os
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit_store import AuditStore
from .gate import PermissionGate
from .models import ApprovalStatus, ToolCall
from .policy_config import load_policy


class CheckResponse(BaseModel):
    verdict: str
    reason: str
    rule: str
    request_id: Optional[str] = None


class ReviewBody(BaseModel):
    by: str = "reviewer"


def create_app(gate: PermissionGate | None = None, agent_key: str | None = None,
               reviewer_key: str | None = None) -> FastAPI:
    if gate is None:
        policy = os.getenv("PERMISSION_GATE_POLICY")
        gate = PermissionGate(config=load_policy(policy) if policy else None,
                              audit_store=AuditStore(os.getenv("PERMISSION_GATE_DB", "audit.db")))
    agent_key = agent_key if agent_key is not None else os.getenv("PERMISSION_GATE_AGENT_KEY")
    reviewer_key = reviewer_key if reviewer_key is not None else os.getenv("PERMISSION_GATE_REVIEWER_KEY")

    def _ok(supplied: Optional[str], *keys: Optional[str]) -> bool:
        configured = [k for k in keys if k]
        if not configured:
            return True
        return supplied is not None and any(hmac.compare_digest(supplied, k) for k in configured)

    def agent_auth(x_api_key: Optional[str] = Header(default=None)) -> None:
        if not _ok(x_api_key, agent_key, reviewer_key):  # reviewers may also act as agents
            raise HTTPException(401, "invalid API key")

    def reviewer_auth(x_api_key: Optional[str] = Header(default=None)) -> None:
        if not _ok(x_api_key, reviewer_key):
            raise HTTPException(401, "reviewer API key required")

    app = FastAPI(title="AI Agent Permission Gate")
    app.state.gate = gate

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.post("/v1/check", response_model=CheckResponse, dependencies=[Depends(agent_auth)])
    def check(call: ToolCall):
        decision, req = gate.submit(call)
        return CheckResponse(verdict=decision.verdict.value, reason=decision.reason,
                             rule=decision.rule, request_id=req.id if req else None)

    @app.get("/v1/requests/{request_id}", dependencies=[Depends(agent_auth)])
    def request_status(request_id: str):
        req = gate.requests.get(request_id)
        if not req:
            raise HTTPException(404, "unknown request")
        return {"id": req.id, "status": req.status.value, "used": req.used}

    @app.post("/v1/requests/{request_id}/consume", dependencies=[Depends(agent_auth)])
    def consume(request_id: str, call: ToolCall):
        """Spend a single-use approval for exactly this call right before executing it."""
        if not gate.consume(request_id, call):
            raise HTTPException(409, "approval unknown, unapproved, used, or for a different call")
        return {"ok": True}

    @app.get("/v1/requests", dependencies=[Depends(reviewer_auth)])
    def list_requests(status: Literal["pending", "approved", "rejected", "all"] = "pending"):
        reqs = list(gate.requests.values())
        if status != "all":
            reqs = [r for r in reqs if r.status is ApprovalStatus(status)]
        return [r.model_dump(mode="json") for r in reqs]

    def _review(request_id: str, approve: bool, body: ReviewBody):
        try:
            req = gate.resolve(request_id, approve, by=body.by)
        except KeyError:
            raise HTTPException(404, "unknown request")
        except ValueError as e:
            raise HTTPException(409, str(e))
        return {"id": req.id, "status": req.status.value}

    @app.post("/v1/requests/{request_id}/approve", dependencies=[Depends(reviewer_auth)])
    def approve(request_id: str, body: ReviewBody = ReviewBody()):
        return _review(request_id, True, body)

    @app.post("/v1/requests/{request_id}/reject", dependencies=[Depends(reviewer_auth)])
    def reject(request_id: str, body: ReviewBody = ReviewBody()):
        return _review(request_id, False, body)

    @app.get("/v1/audit", dependencies=[Depends(reviewer_auth)])
    def audit(limit: int = 100, verdict: Optional[str] = None, final: Optional[str] = None,
              agent: Optional[str] = None):
        if not gate.store:
            raise HTTPException(501, "no audit store configured")
        return gate.store.entries(limit=min(limit, 1000), verdict=verdict, final=final, agent=agent)

    @app.get("/v1/audit/verify", dependencies=[Depends(reviewer_auth)])
    def verify():
        if not gate.store:
            raise HTTPException(501, "no audit store configured")
        ok, bad = gate.store.verify()
        return {"ok": ok, "first_bad_id": bad, "head": gate.store.head(), "entries": gate.store.count()}

    return app


def __getattr__(name: str):  # lazy so importing the module doesn't open a DB; `uvicorn permission_gate.api:app`
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
