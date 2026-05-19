#!/usr/bin/env python3
"""Classify shell commands against the ClawGuard demo allowlist and blocklist."""

from __future__ import annotations

import re
from pathlib import Path

from workspace import get_approved_workspace_prefix

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
    ("ssh_private_read", re.compile(r"~/?\.ssh|/\.ssh/", re.IGNORECASE)),
    ("home_ssh_cat", re.compile(r"\bcat\s+.*\.ssh/", re.IGNORECASE)),
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
    reason, and optional rule_id.
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
        return prefix in command
    return False


def main() -> None:
    import sys

    for cmd in sys.argv[1:] or ["pwd", "rm -rf /", "cat ~/.ssh/id_rsa"]:
        result = classify_command(cmd)
        print(f"{cmd!r} -> {result['status']} ({result['reason']})")


if __name__ == "__main__":
    main()
