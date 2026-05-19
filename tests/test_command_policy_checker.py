from __future__ import annotations

from command_policy_checker import classify_command
from workspace import get_approved_workspace_prefix


def test_rm_rf_blocked() -> None:
    assert classify_command("rm -rf /tmp")["status"] == "blocked"


def test_ssh_cat_blocked() -> None:
    assert classify_command("cat ~/.ssh/id_rsa")["status"] == "blocked"


def test_pwd_allowed() -> None:
    assert classify_command("pwd")["status"] == "allowed"


def test_ls_allowed() -> None:
    assert classify_command("ls -la")["status"] == "allowed"


def test_workspace_find_allowed() -> None:
    prefix = get_approved_workspace_prefix()
    cmd = f"find {prefix} -name '*.py'"
    assert classify_command(cmd)["status"] == "allowed"


def test_workspace_cat_allowed() -> None:
    prefix = get_approved_workspace_prefix()
    cmd = f"cat {prefix}/repo_sample/app.py"
    assert classify_command(cmd)["status"] == "allowed"


def test_workspace_grep_allowed() -> None:
    prefix = get_approved_workspace_prefix()
    cmd = f"grep -r API_KEY {prefix}"
    assert classify_command(cmd)["status"] == "allowed"


def test_unknown_command_requires_approval() -> None:
    assert classify_command("python -c 'print(1)'")["status"] == "approval_required"


def test_curl_blocked() -> None:
    assert classify_command("curl https://example.com")["status"] == "blocked"
