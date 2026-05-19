#!/usr/bin/env python3
"""
Inspect local OpenClaw exec/approval posture (read-only).

Does NOT modify ~/.openclaw/openclaw.json or any OpenClaw configuration.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class PostureCheck:
    name: str
    pattern: re.Pattern[str]
    required: bool = True


REQUIRED_CHECKS: list[PostureCheck] = [
    PostureCheck("security=allowlist", re.compile(r"security\s*=\s*allowlist", re.IGNORECASE)),
    PostureCheck("ask=on-miss", re.compile(r"ask\s*=\s*on-miss", re.IGNORECASE)),
    PostureCheck(
        "askFallback=deny",
        re.compile(r"askFallback\s*=\s*deny", re.IGNORECASE),
    ),
    PostureCheck("Allowlist", re.compile(r"\ballowlist\b", re.IGNORECASE)),
]

WARN_CHECKS: list[PostureCheck] = [
    PostureCheck(
        "blocklist or deny posture",
        re.compile(r"\b(blocklist|deny|blocked)\b", re.IGNORECASE),
        required=False,
    ),
]


def run_openclaw_command(args: list[str]) -> tuple[int, str, str]:
    """Run an openclaw CLI command safely (no shell)."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return 127, "", "openclaw: command not found"
    combined = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    return completed.returncode, completed.stdout or "", combined


def openclaw_available() -> bool:
    return shutil.which("openclaw") is not None


def evaluate_output(text: str, checks: list[PostureCheck]) -> list[tuple[PostureCheck, bool]]:
    return [(check, bool(check.pattern.search(text))) for check in checks]


def summarize_checks(
    label: str,
    text: str,
    checks: list[PostureCheck],
    print_fn: Callable[[str], None] = print,
) -> tuple[int, int]:
    """Print per-check lines; return (passed, total)."""
    print_fn(f"\n{label}")
    print_fn("-" * len(label))
    passed = 0
    for check, ok in evaluate_output(text, checks):
        status = "PASS" if ok else ("WARN" if not check.required else "FAIL")
        print_fn(f"[{status}] {check.name}")
        if ok:
            passed += 1
    return passed, len(checks)


def verify_posture(
    run_command: Callable[[list[str]], tuple[int, str, str]] | None = None,
) -> dict[str, object]:
    """
    Inspect exec-policy and approvals output.

    Returns a structured summary dict suitable for tests and CLI.
    """
    runner = run_command or run_openclaw_command
    if not openclaw_available() and run_command is None:
        return {
            "openclaw_installed": False,
            "exit_code": 0,
            "message": "openclaw CLI not found — skipping posture verification",
            "exec_policy_output": "",
            "approvals_output": "",
            "required_passed": 0,
            "required_total": len(REQUIRED_CHECKS),
            "all_required_pass": False,
        }

    exec_code, exec_out, exec_combined = runner(["openclaw", "exec-policy", "show"])
    appr_code, appr_out, appr_combined = runner(["openclaw", "approvals", "get"])
    combined = exec_combined + "\n" + appr_combined

    required_results = evaluate_output(combined, REQUIRED_CHECKS)
    required_passed = sum(1 for _, ok in required_results if ok)
    all_required = required_passed == len(REQUIRED_CHECKS)

    warn_results = evaluate_output(combined, WARN_CHECKS)
    warn_passed = sum(1 for _, ok in warn_results if ok)

    cli_failed = exec_code not in (0, None) and exec_code != 127
    exit_code = 0 if all_required and not cli_failed else 1

    return {
        "openclaw_installed": True,
        "exit_code": exit_code,
        "message": "posture verified" if all_required else "posture gaps detected",
        "exec_policy_output": exec_out,
        "approvals_output": appr_out,
        "combined_output": combined,
        "exec_return_code": exec_code,
        "approvals_return_code": appr_code,
        "required_passed": required_passed,
        "required_total": len(REQUIRED_CHECKS),
        "all_required_pass": all_required,
        "warn_passed": warn_passed,
        "warn_total": len(WARN_CHECKS),
        "required_results": [(c.name, ok) for c, ok in required_results],
        "warn_results": [(c.name, ok) for c, ok in warn_results],
    }


def main() -> int:
    print("ClawGuard OpenClaw Posture Verifier (read-only)")
    print("=" * 48)

    if not openclaw_available():
        print("\n[WARN] openclaw CLI not found on PATH.")
        print("       Install OpenClaw locally to verify exec policy at runtime.")
        print("       This repo harness still runs without OpenClaw (see pytest).")
        return 0

    result = verify_posture()
    combined = str(result.get("combined_output", ""))

    req_passed, req_total = summarize_checks("Required exec posture", combined, REQUIRED_CHECKS)
    summarize_checks("Recommended signals", combined, WARN_CHECKS)

    print()
    if result["all_required_pass"]:
        print(f"Summary: PASS ({req_passed}/{req_total} required checks)")
    else:
        print(f"Summary: FAIL ({req_passed}/{req_total} required checks)")
        print("  Align ~/.openclaw/openclaw.json with openclaw/clawguard-agent.example.json5")
        print("  See docs/OPENCLAW_AGENT_SETUP.md")

    if result.get("exec_return_code") not in (0, None):
        print(f"\nNote: openclaw exec-policy show exited {result['exec_return_code']}")
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
