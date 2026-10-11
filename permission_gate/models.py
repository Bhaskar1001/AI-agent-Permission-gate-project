from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


# Higher = more restrictive. When several rules match, the strictest wins.
SEVERITY = {Verdict.ALLOW: 0, Verdict.REQUIRE_APPROVAL: 1, Verdict.BLOCK: 2}


class ToolCall(BaseModel):
    """A tool call proposed by an AI agent."""

    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    agent: str = "agent"


class Decision(BaseModel):
    verdict: Verdict
    reason: str
    rule: str = "default"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    call: ToolCall
    decision: Decision
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=_now)
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    used: bool = False  # an approval authorises exactly one execution


class AuditEntry(BaseModel):
    timestamp: datetime = Field(default_factory=_now)
    call: ToolCall
    verdict: Verdict
    reason: str
    rule: str
    final: str  # allowed | blocked | pending | approved | rejected
    request_id: Optional[str] = None
    actor: Optional[str] = None  # who approved/rejected (only set for resolutions)
