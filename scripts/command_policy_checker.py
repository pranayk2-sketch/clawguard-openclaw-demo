#!/usr/bin/env python3
"""Classify shell commands against the ClawGuard demo allowlist and blocklist."""

from __future__ import annotations

import re
from pathlib import Path

from workspace import get_approved_workspace_prefix

SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:~/?\.ssh|/\.ssh/|~/?\.aws|/\.aws/|~/?\.config|/\.config/"
    r"|\.zsh_history|\.bash_history|browser\s+profiles?|/Library/Application Support/Google/Chrome)",
    re.IGNORECASE,
)

BLOCKED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rm_rf", re.compile(r"\brm\s+(-rf\b|-\S*f\S*|\S+\s+-rf\b)", re.IGNORECASE)),
    ("sudo", re.compile(r"\bsudo\b", re.IGNORECASE)),
    ("chmod", re.compile(r"\bchmod\b", re.IGNORECASE)),
    ("chown", re.compile(r"\bchown\b", re.IGNORECASE)),
    ("curl", re.compile(r"\bcurl\b", re.IGNORECASE)),
    ("wget", re.compile(r"\bwget\b", re.IGNORECASE)),
    ("scp", re.compile(r"\bscp\b", re.IGNORECASE)),
    ("rsync", re.compile(r"\brsync\b", re.IGNORECASE)),
    ("brew_install", re.compile(r"\bbrew\s+install\b", re.IGNORECASE)),
    ("npm_install", re.compile(r"\bnpm\s+install\b", re.IGNORECASE)),
    ("pip_install", re.compile(r"\bpip\s+install\b", re.IGNORECASE)),
    ("sensitive_path", SENSITIVE_PATH_PATTERN),
    ("path_traversal", re.compile(r"(?:^|\s)(?:\.\./)+|(?:^|\s)/etc/|(?:^|\s)/var/", re.IGNORECASE)),
    ("absolute_outside_workspace", re.compile(r"\bcat\s+/(?!Users/)", re.IGNORECASE)),
    (
        "python_c_exfil",
        re.compile(
            r"python3?\s+-c\b.*(?:urllib|requests|http\.client|socket|curl|wget|open\s*\()",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]

ALLOWED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pwd", re.compile(r"^\s*pwd\s*$", re.IGNORECASE)),
    ("ls", re.compile(r"^\s*ls\b", re.IGNORECASE)),
    (
        "find_workspace",
        re.compile(
            rf"^\s*find\s+{re.escape(get_approved_workspace_prefix())}",
            re.IGNORECASE,
        ),
    ),
    (
        "cat_workspace",
        re.compile(
            rf"^\s*cat\s+{re.escape(get_approved_workspace_prefix())}",
            re.IGNORECASE,
        ),
    ),
    (
        "grep_workspace",
        re.compile(
            rf"^\s*grep\b.*\s+{re.escape(get_approved_workspace_prefix())}",
            re.IGNORECASE,
        ),
    ),
]


def _normalize(command: str) -> str:
    expanded = command.replace("~/", f"{Path.home()}/")
    return " ".join(expanded.split())


def classify_command(command: str) -> dict[str, str]:
    """
    Classify a shell command string.

    Returns a dict with keys: status (allowed|blocked|approval_required),
    reason, and rule_id.
    """
    normalized = _normalize(command.strip())
    if not normalized:
        return {
            "status": "approval_required",
            "reason": "empty command",
            "rule_id": "empty",
        }

    for rule_id, pattern in BLOCKED_PATTERNS:
        if pattern.search(normalized):
            return {
                "status": "blocked",
                "reason": f"matches blocked pattern: {rule_id}",
                "rule_id": rule_id,
            }

    for rule_id, pattern in ALLOWED_PATTERNS:
        if pattern.search(normalized):
            if _command_stays_in_workspace(normalized, rule_id):
                return {
                    "status": "allowed",
                    "reason": f"matches allowlist: {rule_id}",
                    "rule_id": rule_id,
                }
            return {
                "status": "blocked",
                "reason": "path outside approved workspace",
                "rule_id": "workspace_boundary",
            }

    return {
        "status": "approval_required",
        "reason": "not on allowlist; requires exec approval",
        "rule_id": "unknown",
    }


def _command_stays_in_workspace(command: str, rule_id: str) -> bool:
    """Ensure cat/find/grep targets remain under the approved workspace."""
    prefix = get_approved_workspace_prefix()
    if rule_id in {"pwd", "ls"}:
        return True
    if rule_id in {"find_workspace", "cat_workspace", "grep_workspace"}:
        if ".." in command:
            return False
        return prefix in command
    return False


def main() -> None:
    import sys

    for cmd in sys.argv[1:] or ["pwd", "rm -rf /", "cat ~/.ssh/id_rsa"]:
        result = classify_command(cmd)
        print(f"{cmd!r} -> {result['status']} ({result['reason']})")


if __name__ == "__main__":
    main()
