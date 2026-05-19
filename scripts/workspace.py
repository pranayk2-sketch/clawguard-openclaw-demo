"""Resolve the ClawGuard demo workspace root."""

from __future__ import annotations

from pathlib import Path

WORKSPACE_NAME = "clawguard-demo-workspace"


def get_repo_root() -> Path:
    """Return repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def get_approved_workspace_prefix() -> str:
    """Path prefix used in allowlisted shell commands (tilde-expanded at check time)."""
    home = Path.home()
    return str(home / "Desktop" / WORKSPACE_NAME)
