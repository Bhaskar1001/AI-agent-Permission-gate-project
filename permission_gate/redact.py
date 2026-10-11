"""Scrub secrets from tool-call arguments before they are written to the audit log."""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Argument names whose values are secrets, however deeply nested.
_SECRET_KEY = re.compile(
    r"pass(word|wd)?|secret|token|api[-_ ]?key|authorization|cookie|credential|private[-_ ]?key|bearer",
    re.I)

# Secrets embedded in free text (e.g. a shell command or URL).
_SECRET_TEXT = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), rf"\1 {REDACTED}"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key)\b(\s*[=:]\s*)[^\s&'\"]+"),
     rf"\1\2{REDACTED}"),
    (re.compile(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{8,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+@"), rf"\1{REDACTED}@"),  # user:password@host
]


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: REDACTED if _SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for pattern, repl in _SECRET_TEXT:
            value = pattern.sub(repl, value)
    return value
