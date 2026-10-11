"""Rule-based policy. Default deny: unknown tools are blocked."""
from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from urllib.parse import urlsplit
from typing import Callable, Optional

from .models import SEVERITY, Decision, ToolCall, Verdict

READ_TOOLS = {"read_file", "list_dir", "search_files"}
WRITE_TOOLS = {"write_file", "edit_file", "create_file", "move_file"}
DELETE_TOOLS = {"delete_file", "delete_dir"}
SHELL_TOOLS = {"run_shell"}
NETWORK_TOOLS = {"http_request"}

# Path segments / names that mark a location as protected.
PROD_SEGMENTS = {"prod", "production"}
SENSITIVE_PATTERNS = [
    r"(^|/)\.env(\..*)?$",
    r"(^|/)\.ssh(/|$)",
    r"(^|/)id_(rsa|ed25519)(\.pub)?$",
    r"^/etc/(shadow|passwd|sudoers)",
    r"\.(pem|key)$",
]

DANGEROUS_SHELL = [
    r"\brm\s+(-\w*[rf]\w*\s+)+",
    r"\brm\s+.*--(recursive|force|no-preserve-root)\b",
    r"\b(rmdir|rd)\s+.*/s\b",
    r"\bsudo\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+(-R\s+)?7[0-7]{2}\b",
    r"(curl|wget)[^|]*\|\s*(sh|bash)",
    r":\(\)\s*\{",
    r">\s*/dev/sd",
    r"\bshutdown\b|\breboot\b",
    r"\bformat\s+[a-z]:",
    r"\bdel\s+/[sfq]",
    r"\bRemove-Item\b.*-Recurse",
]
SAFE_SHELL = {"ls", "pwd", "whoami", "date", "echo", "cat", "head", "tail", "git status",
              "git log", "git diff", "dir", "type"}
SHELL_CHAINING = re.compile(r"[;&|`\r\n]|\$\(|>")  # newline starts a second command too


def normalize_path(raw: str) -> str:
    """Normalise separators and collapse ../ so traversal can't hide a protected path."""
    p = raw.strip().replace("\\", "/")
    p = re.sub(r"^[A-Za-z]:", "", p)  # drop Windows drive letter
    # Windows resolves "prod." and "prod " to "prod"; do the same before comparing segments.
    p = "/".join(s if s in (".", "..") else s.rstrip(". ") for s in p.split("/"))
    return posixpath.normpath(p) if p else "."


def _path_of(call: ToolCall) -> Optional[str]:
    for key in ("path", "file", "directory", "dir", "src", "dest"):
        val = call.args.get(key)
        if isinstance(val, str) and val:
            return normalize_path(val)
    return None


def _paths_of(call: ToolCall) -> list[str]:
    out = []
    for key in ("path", "file", "directory", "dir", "src", "dest"):
        val = call.args.get(key)
        if isinstance(val, str) and val:
            out.append(normalize_path(val))
    return out


def _is_prod(path: str) -> bool:
    return any(seg.lower() in PROD_SEGMENTS for seg in path.split("/"))


def _is_sensitive(path: str) -> bool:
    return any(re.search(p, path, re.I) for p in SENSITIVE_PATTERNS)


def _is_root_like(path: str) -> bool:
    return path in {"/", ".", "..", "~"} or path.startswith("../")


Rule = Callable[[ToolCall], Optional[Decision]]


def rule_unknown_tool(call: ToolCall) -> Optional[Decision]:
    known = READ_TOOLS | WRITE_TOOLS | DELETE_TOOLS | SHELL_TOOLS | NETWORK_TOOLS
    if call.tool not in known:
        return Decision(verdict=Verdict.BLOCK, rule="unknown_tool",
                        reason=f"Tool '{call.tool}' is not recognised (default deny).")
    return None


def rule_path_tools(call: ToolCall) -> Optional[Decision]:
    if call.tool not in READ_TOOLS | WRITE_TOOLS | DELETE_TOOLS:
        return None
    paths = _paths_of(call)
    if not paths:
        return Decision(verdict=Verdict.BLOCK, rule="missing_path",
                        reason="No path supplied; cannot assess the target.")
    decisions = []
    for path in paths:
        if call.tool in DELETE_TOOLS:
            if _is_prod(path):
                decisions.append(Decision(verdict=Verdict.BLOCK, rule="delete_prod",
                                          reason=f"Deleting production path '{path}' is never allowed."))
            elif _is_root_like(path) or path.count("/") == 0 and call.tool == "delete_dir" and path in {"."}:
                decisions.append(Decision(verdict=Verdict.BLOCK, rule="delete_root",
                                          reason=f"Deleting '{path}' would wipe a root/workspace directory."))
            elif _is_sensitive(path):
                decisions.append(Decision(verdict=Verdict.BLOCK, rule="delete_sensitive",
                                          reason=f"'{path}' is a sensitive file."))
            else:
                decisions.append(Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="delete",
                                          reason=f"Deletion of '{path}' is destructive; human approval needed."))
        elif call.tool in WRITE_TOOLS:
            if _is_sensitive(path):
                decisions.append(Decision(verdict=Verdict.BLOCK, rule="write_sensitive",
                                          reason=f"Writing to sensitive path '{path}' is blocked."))
            elif _is_prod(path):
                decisions.append(Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="write_prod",
                                          reason=f"'{path}' is in a production location; approval required."))
            else:
                decisions.append(Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="write",
                                          reason=f"Modifying '{path}' changes state; approval required."))
        else:  # read
            if _is_sensitive(path):
                decisions.append(Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="read_sensitive",
                                          reason=f"'{path}' may contain secrets; approval required."))
            else:
                decisions.append(Decision(verdict=Verdict.ALLOW, rule="read",
                                          reason=f"Read-only access to '{path}'."))
    return max(decisions, key=lambda d: SEVERITY[d.verdict])


def rule_shell(call: ToolCall) -> Optional[Decision]:
    if call.tool not in SHELL_TOOLS:
        return None
    cmd = str(call.args.get("command", "")).strip()
    if not cmd:
        return Decision(verdict=Verdict.BLOCK, rule="shell_empty", reason="Empty command.")
    for pat in DANGEROUS_SHELL:
        if re.search(pat, cmd, re.I):
            return Decision(verdict=Verdict.BLOCK, rule="shell_dangerous",
                            reason=f"Command matches dangerous pattern: {pat}")
    if any(_is_sensitive(normalize_path(tok)) for tok in cmd.split()[1:]):
        return Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="shell_sensitive",
                        reason="Command touches a sensitive path.")
    if not SHELL_CHAINING.search(cmd) and any(cmd == s or cmd.startswith(s + " ") for s in SAFE_SHELL):
        return Decision(verdict=Verdict.ALLOW, rule="shell_safe", reason="Known read-only command.")
    return Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="shell_other",
                    reason="Shell command is not on the safe list; approval required.")


INTERNAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".intranet", ".lan")


def _host_ip(host: str):
    """Parse a host as an IP, including the decimal/hex/octal IPv4 forms (2130706433, 0x7f000001)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def _is_internal_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(INTERNAL_HOST_SUFFIXES):
        return True
    ip = _host_ip(host)
    if ip is None:
        return False  # public-looking hostname; DNS is not resolved here
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return not ip.is_global


def rule_network(call: ToolCall) -> Optional[Decision]:
    if call.tool not in NETWORK_TOOLS:
        return None
    method = str(call.args.get("method", "GET")).upper()
    url = str(call.args.get("url", ""))
    if re.search(r"[\s\x00-\x1f]", url):
        return Decision(verdict=Verdict.BLOCK, rule="net_malformed", reason="URL contains whitespace or control characters.")
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return Decision(verdict=Verdict.BLOCK, rule="net_malformed", reason="URL could not be parsed safely.")
    if parts.scheme.lower() not in ("http", "https"):
        return Decision(verdict=Verdict.BLOCK, rule="net_scheme", reason="Only http(s) URLs are permitted.")
    if _is_internal_host(host):
        return Decision(verdict=Verdict.BLOCK, rule="net_internal",
                        reason="Requests to internal/metadata addresses are blocked (SSRF).")
    if method in {"GET", "HEAD"}:
        return Decision(verdict=Verdict.ALLOW, rule="net_read", reason=f"{method} to external URL.")
    return Decision(verdict=Verdict.REQUIRE_APPROVAL, rule="net_write",
                    reason=f"{method} request sends data externally; approval required.")


DEFAULT_RULES: list[Rule] = [rule_unknown_tool, rule_path_tools, rule_shell, rule_network]


def evaluate(call: ToolCall, rules: list[Rule] | None = None) -> Decision:
    """Run all rules; the most restrictive matching decision wins."""
    decisions = [d for r in (rules or DEFAULT_RULES) if (d := r(call)) is not None]
    if not decisions:
        return Decision(verdict=Verdict.BLOCK, rule="no_match", reason="No rule matched (default deny).")
    return max(decisions, key=lambda d: SEVERITY[d.verdict])
