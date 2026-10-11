"""YAML-driven, per-agent role policies layered on top of the built-in rules.

Roles can tighten the built-in decision freely. They can only *relax* a plain
REQUIRE_APPROVAL to ALLOW, never a BLOCK and never a protected prod/sensitive path.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, model_validator

from .models import SEVERITY, Decision, ToolCall, Verdict
from .policy import Rule, _paths_of, evaluate

# Built-in rules a role is never allowed to relax.
NON_RELAXABLE = {"read_sensitive", "write_prod", "shell_sensitive"}


class CustomRule(BaseModel):
    name: str
    tools: list[str] = Field(default_factory=list)  # empty = any tool
    path_glob: Optional[str] = None  # matched against normalised paths
    command_regex: Optional[str] = None  # matched against args["command"]
    verdict: Verdict
    reason: str = ""

    def matches(self, call: ToolCall) -> bool:
        if self.tools and call.tool not in self.tools:
            return False
        if self.path_glob is not None and not any(
                fnmatch.fnmatchcase(p, self.path_glob) for p in _paths_of(call)):
            return False
        if self.command_regex is not None and not re.search(
                self.command_regex, str(call.args.get("command", "")), re.I):
            return False
        return True


class RolePolicy(BaseModel):
    allowed_tools: Optional[list[str]] = None  # None = no tool restriction
    rules: list[CustomRule] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    default_role: str = "default"
    roles: dict[str, RolePolicy] = Field(default_factory=lambda: {"default": RolePolicy()})
    agents: dict[str, str] = Field(default_factory=dict)  # agent name or glob -> role

    @model_validator(mode="after")
    def _check_roles(self) -> "PolicyConfig":
        self.roles.setdefault("default", RolePolicy())
        for target in [self.default_role, *self.agents.values()]:
            if target not in self.roles:
                raise ValueError(f"unknown role '{target}'")
        return self

    def role_for(self, agent: str) -> str:
        for pattern, role in self.agents.items():
            if fnmatch.fnmatchcase(agent, pattern):
                return role
        return self.default_role


def load_policy(path: str | Path) -> PolicyConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return PolicyConfig.model_validate(data)


def evaluate_with_config(call: ToolCall, config: PolicyConfig,
                         rules: list[Rule] | None = None) -> Decision:
    base = evaluate(call, rules)
    if base.verdict is Verdict.BLOCK:
        return base

    role = config.role_for(call.agent)
    rp = config.roles[role]

    if rp.allowed_tools is not None and call.tool not in rp.allowed_tools:
        return Decision(verdict=Verdict.BLOCK, rule=f"role:{role}:tool_not_allowed",
                        reason=f"Role '{role}' may not use '{call.tool}'.")

    matched = [r for r in rp.rules if r.matches(call)]

    stricter = [r for r in matched if SEVERITY[r.verdict] > SEVERITY[base.verdict]]
    if stricter:
        r = max(stricter, key=lambda r: SEVERITY[r.verdict])
        return Decision(verdict=r.verdict, rule=f"role:{role}:{r.name}",
                        reason=r.reason or f"Role '{role}' rule '{r.name}'.")

    if (base.verdict is Verdict.REQUIRE_APPROVAL and base.rule not in NON_RELAXABLE
            and any(r.verdict is Verdict.ALLOW for r in matched)
            and not any(r.verdict is not Verdict.ALLOW for r in matched)):
        r = next(r for r in matched if r.verdict is Verdict.ALLOW)
        return Decision(verdict=Verdict.ALLOW, rule=f"role:{role}:{r.name}",
                        reason=r.reason or f"Pre-approved by role '{role}' rule '{r.name}'.")
    return base
