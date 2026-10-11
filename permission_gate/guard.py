"""`gated_tool`: wrap a plain function so the gate decides whether it may run."""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
from typing import Any, Callable, Optional, Union

from .gate import PermissionGate
from .models import ApprovalRequest, ApprovalStatus, Decision, ToolCall, Verdict


class PermissionDenied(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


class ApprovalRequired(Exception):
    """Raised when a human must approve first. Retry with `_approval_id=<request.id>` once approved."""

    def __init__(self, request: ApprovalRequest):
        super().__init__(f"Approval required (request {request.id}): {request.decision.reason}")
        self.request = request


class ApprovalRejected(PermissionDenied):
    pass


class ApprovalTimeout(Exception):
    def __init__(self, request: ApprovalRequest):
        super().__init__(f"No decision on request {request.id} in time")
        self.request = request


def _jsonable(v: Any) -> Any:
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return repr(v)


def gated_tool(gate: PermissionGate, tool: Optional[str] = None,
               agent: Union[str, Callable[[], str]] = "agent",
               wait: Optional[float] = None) -> Callable:
    """Decorator. `tool` defaults to the function name; call args become `ToolCall.args`.

    ALLOW -> runs. BLOCK -> PermissionDenied. REQUIRE_APPROVAL ->
      * wait=None: raises ApprovalRequired (retry later with `_approval_id=`)
      * wait=N:    blocks up to N seconds for a human, then runs / ApprovalRejected / ApprovalTimeout
    """

    def decorator(fn: Callable) -> Callable:
        name = tool or fn.__name__
        sig = inspect.signature(fn)

        def build(args: tuple, kwargs: dict) -> ToolCall:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            who = agent() if callable(agent) else agent
            return ToolCall(tool=name, agent=who,
                            args={k: _jsonable(v) for k, v in bound.arguments.items()})

        def check(call: ToolCall, approval_id: Optional[str]) -> Optional[ApprovalRequest]:
            """Returns None if the call may run now, else the request to wait on."""
            if approval_id is not None:
                if gate.consume(approval_id, call):
                    return None
                raise PermissionDenied(Decision(
                    verdict=Verdict.BLOCK, rule="bad_approval",
                    reason="Approval id is unknown, unapproved, already used, or for a different call."))
            decision, req = gate.submit(call)
            if decision.verdict is Verdict.ALLOW:
                return None
            if decision.verdict is Verdict.BLOCK:
                raise PermissionDenied(decision)
            if wait is None:
                raise ApprovalRequired(req)
            return req

        def finish(req: ApprovalRequest, status: ApprovalStatus, call: ToolCall) -> None:
            if status is ApprovalStatus.PENDING:
                raise ApprovalTimeout(req)
            if status is ApprovalStatus.REJECTED or not gate.consume(req.id, call):
                raise ApprovalRejected(Decision(verdict=Verdict.BLOCK, rule="rejected",
                                                reason=f"Request {req.id} was rejected."))

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args, _approval_id: Optional[str] = None, **kwargs):
                call = build(args, kwargs)
                req = check(call, _approval_id)
                if req is not None:
                    finish(req, await asyncio.to_thread(gate.wait_for, req.id, wait), call)
                return await fn(*args, **kwargs)
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, _approval_id: Optional[str] = None, **kwargs):
            call = build(args, kwargs)
            req = check(call, _approval_id)
            if req is not None:
                finish(req, gate.wait_for(req.id, wait), call)
            return fn(*args, **kwargs)
        return wrapper

    return decorator
