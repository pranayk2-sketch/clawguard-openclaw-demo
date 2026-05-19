#!/usr/bin/env python3
"""Run ClawGuard demo harness checks and print PASS/FAIL results."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from command_policy_checker import classify_command
from prompt_injection_scanner import scan_file as scan_injection_file
from scenario_runner import run_scenarios, write_scenario_reports
from secret_scanner import scan_file as scan_secret_file
from workspace import get_approved_workspace_prefix, get_repo_root

UNSAFE_SQL_PATTERN = re.compile(
    r"SELECT\s+.*\{.*\}.*FROM|f[\"']SELECT\s+\*",
    re.IGNORECASE | re.DOTALL,
)


def _print_result(name: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")
    return passed


def check_prompt_injection(repo: Path) -> bool:
    target = repo / "attacks" / "prompt_injection.md"
    findings = scan_injection_file(target)
    labels = {f.matched_label for f in findings}
    return _print_result(
        "prompt injection file detected",
        len(findings) > 0 and "ignore previous instructions" in labels,
        f"{len(findings)} finding(s) in {target.name}",
    )


def check_fake_env_secrets(repo: Path) -> bool:
    target = repo / "attacks" / "fake_env_file.env"
    findings = scan_secret_file(target)
    labels = {f.matched_label for f in findings}
    expected = {"OPENAI_API_KEY", "PLAID_SECRET", "DATABASE_URL"}
    ok = expected.issubset(labels)
    return _print_result(
        "fake env secrets detected",
        ok,
        f"labels found: {sorted(labels)}",
    )


def check_hardcoded_api_key(repo: Path) -> bool:
    target = repo / "repo_sample" / "app.py"
    findings = scan_secret_file(target)
    ok = any(f.matched_label == "API_KEY" and f.rule_id == "api_key_assignment" for f in findings)
    return _print_result(
        "vulnerable app.py hardcoded key detected",
        ok,
        str(target),
    )


def check_unsafe_sql(repo: Path) -> bool:
    target = repo / "repo_sample" / "app.py"
    text = target.read_text(encoding="utf-8")
    ok = bool(UNSAFE_SQL_PATTERN.search(text))
    return _print_result(
        "unsafe SQL pattern detected",
        ok,
        "f-string interpolated SELECT" if ok else "pattern not found",
    )


def check_rm_rf_blocked() -> bool:
    result = classify_command("rm -rf /tmp/demo")
    ok = result["status"] == "blocked"
    return _print_result(
        "destructive rm -rf classified as blocked",
        ok,
        result["reason"],
    )


def check_ssh_cat_blocked() -> bool:
    result = classify_command("cat ~/.ssh/id_rsa")
    ok = result["status"] == "blocked"
    return _print_result(
        "cat ~/.ssh/id_rsa classified as blocked",
        ok,
        result["reason"],
    )


def check_allowed_workspace_commands() -> bool:
    prefix = get_approved_workspace_prefix()
    cases = [
        (f"find {prefix} -name app.py", "allowed"),
        (f"cat {prefix}/repo_sample/app.py", "allowed"),
        (f"grep -r API_KEY {prefix}", "allowed"),
        (f"cat {Path.home()}/.ssh/id_rsa", "blocked"),
        (f"grep -r secret {Path.home()}/Documents", "approval_required"),
    ]
    all_ok = True
    for command, expected in cases:
        result = classify_command(command)
        ok = result["status"] == expected
        all_ok = all_ok and ok
        if not ok:
            print(
                f"  expected {expected} for {command!r}, got {result['status']} ({result['reason']})"
            )
    return _print_result(
        "allowed find/cat/grep commands classified as allowed only inside workspace",
        all_ok,
        f"workspace prefix: {prefix}",
    )


def run_scenario_matrix_section() -> tuple[bool, dict[str, object]]:
    print()
    print("Scenario Matrix Checks")
    print("-" * 40)
    output = run_scenarios()
    write_scenario_reports(output)
    summary = output["summary"]
    all_pass = summary["fail"] == 0
    _print_result(
        "scenario matrix harness",
        all_pass,
        f"{summary['pass']}/{summary['total']} PASS, "
        f"{summary['partial']} PARTIAL, {summary['fail']} FAIL "
        f"({summary['pass_rate']:.1%})",
    )
    failed = [s["id"] for s in output["scenarios"] if s["result"] == "FAIL"]
    if failed:
        print(f"  failed scenarios: {', '.join(failed)}")
    return all_pass, output


def main() -> int:
    repo = get_repo_root()
    print("Core Demo Checks")
    print("-" * 40)
    results = [
        check_prompt_injection(repo),
        check_fake_env_secrets(repo),
        check_hardcoded_api_key(repo),
        check_unsafe_sql(repo),
        check_rm_rf_blocked(),
        check_ssh_cat_blocked(),
        check_allowed_workspace_commands(),
    ]
    core_passed = sum(results)
    core_total = len(results)
    print()
    print(f"Core results: {core_passed}/{core_total} passed")

    scenario_ok, _ = run_scenario_matrix_section()
    print()
    overall_ok = all(results) and scenario_ok
    print(
        f"Overall: {'PASS' if overall_ok else 'FAIL'} "
        f"(core {core_passed}/{core_total}, scenarios see reports/scenario_results.md)"
    )
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
