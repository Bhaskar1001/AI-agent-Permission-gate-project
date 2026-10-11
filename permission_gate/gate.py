from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from .audit_store import AuditStore
from .models import (ApprovalRequest, ApprovalStatus, AuditEntry, Decision,
                     ToolCall, Verdict, _now)
from .policy import Rule, evaluate
from .redact import redact
from .policy_config import PolicyConfig, evaluate_with_config


class PermissionGate:
    """Decides allow / block / ask-human for each proposed tool call and keeps an audit trail."""

    def __init__(self, rules: list[Rule] | None = None, audit_path: str | Path | None = None,
                 config: PolicyConfig | None = None, audit_store: AuditStore | None = None):
        self.rules = rules
        self.config = config
        self.audit_path = Path(audit_path) if audit_path else None
        self.store = audit_store
        self.audit: list[AuditEntry] = []
        self.requests: dict[str, ApprovalRequest] = {}
        self._cond = threading.Condition(threading.RLock())

    # -- core -----------------------------------------------------------
    def decide(self, call: ToolCall) -> Decision:
        if self.config:
            return evaluate_with_config(call, self.config, self.rules)
        return evaluate(call, self.rules)

    def submit(self, call: ToolCall) -> tuple[Decision, Optional[ApprovalRequest]]:
        decision = self.decide(call)
        request = None
        with self._cond:
            if decision.verdict is Verdict.ALLOW:
                final = "allowed"
            elif decision.verdict is Verdict.BLOCK:
                final = "blocked"
            else:
                request = ApprovalRequest(call=call, decision=decision)
                self.requests[request.id] = request
                final = "pending"
            self._log(call, decision, final, request.id if request else None)
        return decision, request

    def resolve(self, request_id: str, approve: bool, by: str = "human") -> ApprovalRequest:
        with self._cond:
            req = self.requests[request_id]
            if req.status is not ApprovalStatus.PENDING:
                raise ValueError(f"Request {request_id} already {req.status.value}")
            req.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
            req.resolved_at, req.resolved_by = _now(), by
            self._log(req.call, req.decision, req.status.value, req.id, actor=by)
            self._cond.notify_all()
            return req

    def wait_for(self, request_id: str, timeout: float | None = None) -> ApprovalStatus:
        """Block until the request is resolved (or timeout). Still PENDING on timeout."""
        with self._cond:
            req = self.requests[request_id]
            self._cond.wait_for(lambda: req.status is not ApprovalStatus.PENDING, timeout)
            return req.status

    def is_permitted(self, request_id: str) -> bool:
        return self.requests[request_id].status is ApprovalStatus.APPROVED

    def consume(self, request_id: str, call: ToolCall) -> bool:
        """Spend a single-use approval. Only valid for the exact call that was approved."""
        with self._cond:
            req = self.requests.get(request_id)
            if (req is None or req.status is not ApprovalStatus.APPROVED or req.used
                    or req.call.tool != call.tool or req.call.args != call.args
                    or req.call.agent != call.agent):  # approval belongs to the requesting agent
                return False
            req.used = True
            self._log(req.call, req.decision, "executed", req.id)
            return True

    def pending(self) -> list[ApprovalRequest]:
        with self._cond:
            return [r for r in self.requests.values() if r.status is ApprovalStatus.PENDING]

    # -- audit ----------------------------------------------------------
    def _log(self, call: ToolCall, d: Decision, final: str, request_id: Optional[str],
             actor: Optional[str] = None) -> None:
        # Secrets are scrubbed here; the in-memory request keeps the real args for the reviewer.
        safe = call.model_copy(update={"args": redact(call.args)})
        entry = AuditEntry(call=safe, verdict=d.verdict, reason=d.reason, rule=d.rule,
                           final=final, request_id=request_id, actor=actor)
        self.audit.append(entry)
        if self.store:
            self.store.append(entry)
        if self.audit_path:
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(json.loads(entry.model_dump_json())) + "\n")
