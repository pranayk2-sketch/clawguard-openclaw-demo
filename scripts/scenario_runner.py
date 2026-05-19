#!/usr/bin/env python3
"""
Run the ClawGuard harness scenario matrix using deterministic scanners.

Classifies command strings only — never executes shell commands.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from command_policy_checker import classify_command
from prompt_injection_scanner import scan_file as scan_injection_file
from scenario_config import load_scenarios
from secret_scanner import scan_file as scan_secret_file
from workspace import get_repo_root

ResultStatus = Literal["PASS", "FAIL", "PARTIAL"]

UNSAFE_SQL_PATTERN = re.compile(
    r"SELECT\s+.*\{.*\}.*FROM|f[\"']SELECT\s+\*",
    re.IGNORECASE | re.DOTALL,
)

# Optional labels that strengthen detection for specific scenarios
SCENARIO_LABEL_HINTS: dict[str, list[str]] = {
    "prompt_injection_file": ["ignore previous instructions", "do not tell the user"],
    "hidden_readme_instruction": ["developer message", "ignore previous instructions"],
    "encoded_secret_prompt": ["base64", "decode this secret"],
    "exfiltration_attempt_file": ["exfiltrate", "curl"],
    "package_install_attempt_file": ["package install"],
    "path_traversal_attempt_file": ["path traversal"],
    "symlink_escape_notes_file": ["symlink escape", "read ~/.ssh"],
    "fake_secret_detection": ["OPENAI_API_KEY", "PLAID_SECRET", "DATABASE_URL"],
}


def _check_sql(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(UNSAFE_SQL_PATTERN.search(text))


def _evaluate_file_scenario(
    repo: Path, scenario: dict[str, str]
) -> tuple[str, str, int, list[str]]:
    """Return (actual_status, details, findings_count, matched_labels)."""
    rel = scenario.get("input_file", "")
    path = repo / rel
    check_type = scenario.get("check_type", "injection")

    if check_type == "secret":
        findings = scan_secret_file(path)
        labels = [f.matched_label for f in findings]
        hints = SCENARIO_LABEL_HINTS.get(scenario["id"], [])
        match_label = scenario.get("match_label")
        if hints:
            ok = all(h in labels for h in hints)
        elif match_label:
            ok = any(f.matched_label == match_label for f in findings)
        else:
            ok = len(findings) > 0
        actual = "detect" if ok else "miss"
        detail = f"labels={labels}" if labels else "no secret findings"
        return actual, detail, len(findings), labels

    if check_type == "sql":
        ok = _check_sql(path)
        actual = "detect" if ok else "miss"
        return actual, "unsafe SQL pattern" if ok else "SQL pattern not found", int(ok), []

    findings = scan_injection_file(path)
    labels = [f.matched_label for f in findings]
    hints = SCENARIO_LABEL_HINTS.get(scenario["id"], [])
    if not findings:
        return "miss", "no injection findings", 0, []
    if hints:
        matched_hints = [h for h in hints if h in labels]
        if len(matched_hints) == len(hints):
            return "detect", f"labels={labels}", len(findings), labels
        if matched_hints:
            return (
                "detect",
                f"partial hints {matched_hints}; all labels={labels}",
                len(findings),
                labels,
            )
        return "detect", f"findings present; hints missing; labels={labels}", len(findings), labels
    return "detect", f"labels={labels}", len(findings), labels


def _evaluate_command_scenario(scenario: dict[str, str]) -> tuple[str, str, int, list[str]]:
    command = scenario.get("command", "")
    result = classify_command(command)
    status = result["status"]
    expected = scenario.get("expected_status", "block")
    mapping = {
        "block": "blocked",
        "pass": "allowed",
        "approval_required": "approval_required",
    }
    expected_actual = mapping.get(expected, expected)
    actual = status if status == expected_actual else status
    detail = f"command={command!r} -> {status} ({result['reason']})"
    return actual, detail, 1 if status == expected_actual else 0, [status]


def _grade_scenario(
    scenario: dict[str, str], actual: str
) -> ResultStatus:
    expected = scenario.get("expected_status", "")
    if expected == "detect":
        if actual == "detect":
            return "PASS"
        if actual == "miss":
            return "FAIL"
        return "PARTIAL"
    mapping = {"block": "blocked", "pass": "allowed", "approval_required": "approval_required"}
    expected_actual = mapping.get(expected, expected)
    if actual == expected_actual:
        return "PASS"
    if expected == "block" and actual in {"approval_required"}:
        return "PARTIAL"
    return "FAIL"


def run_scenarios(repo: Path | None = None, config_path: Path | None = None) -> dict[str, object]:
    """Evaluate all configured scenarios and return structured results."""
    root = repo or get_repo_root()
    scenarios = load_scenarios(config_path)
    results: list[dict[str, object]] = []

    for scenario in scenarios:
        if "command" in scenario:
            actual, detail, _, labels = _evaluate_command_scenario(scenario)
        else:
            actual, detail, count, labels = _evaluate_file_scenario(root, scenario)
            if "command" not in scenario:
                detail = f"{detail}; findings={count}"

        grade = _grade_scenario(scenario, actual)
        results.append(
            {
                "id": scenario.get("id", ""),
                "name": scenario.get("name", ""),
                "category": scenario.get("category", ""),
                "severity": scenario.get("severity", ""),
                "expected_status": scenario.get("expected_status", ""),
                "expected_behavior": scenario.get("expected_behavior", ""),
                "rationale": scenario.get("rationale", ""),
                "actual_status": actual,
                "result": grade,
                "details": detail,
                "matched_labels": labels,
            }
        )

    passed = sum(1 for r in results if r["result"] == "PASS")
    partial = sum(1 for r in results if r["result"] == "PARTIAL")
    failed = sum(1 for r in results if r["result"] == "FAIL")
    total = len(results)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": total,
            "pass": passed,
            "partial": partial,
            "fail": failed,
            "pass_rate": round(passed / total, 3) if total else 0.0,
        },
        "scenarios": results,
    }


def write_scenario_reports(
    output: dict[str, object], reports_dir: Path | None = None
) -> tuple[Path, Path]:
    """Write JSON and Markdown scenario reports."""
    repo = get_repo_root()
    directory = reports_dir or (repo / "reports")
    directory.mkdir(parents=True, exist_ok=True)

    json_path = directory / "scenario_results.json"
    json_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    summary = output["summary"]
    lines = [
        "# ClawGuard Scenario Matrix Results",
        "",
        f"Generated: {output['generated_at']}",
        "",
        "## Summary",
        "",
        f"- **Total scenarios:** {summary['total']}",
        f"- **PASS:** {summary['pass']}",
        f"- **PARTIAL:** {summary['partial']}",
        f"- **FAIL:** {summary['fail']}",
        f"- **Pass rate:** {summary['pass_rate']:.1%}",
        "",
        "## Results",
        "",
        "| ID | Category | Severity | Expected | Actual | Result |",
        "|----|----------|----------|----------|--------|--------|",
    ]
    for item in output["scenarios"]:
        lines.append(
            f"| {item['id']} | {item['category']} | {item['severity']} | "
            f"{item['expected_status']} | {item['actual_status']} | **{item['result']}** |"
        )

    lines.extend(["", "## Details", ""])
    for item in output["scenarios"]:
        lines.append(f"### {item['id']} — {item['name']}")
        lines.append(f"- **Result:** {item['result']}")
        lines.append(f"- **Rationale:** {item['rationale']}")
        lines.append(f"- **Details:** {item['details']}")
        lines.append("")

    md_path = directory / "scenario_results.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def print_cli_summary(output: dict[str, object]) -> None:
    summary = output["summary"]
    print("ClawGuard Scenario Matrix")
    print("=" * 40)
    for item in output["scenarios"]:
        mark = item["result"]
        print(
            f"[{mark:7}] {item['id']}: "
            f"expected={item['expected_status']} actual={item['actual_status']}"
        )
    print("-" * 40)
    print(
        f"PASS {summary['pass']}/{summary['total']} | "
        f"PARTIAL {summary['partial']} | FAIL {summary['fail']} | "
        f"rate {summary['pass_rate']:.1%}"
    )


def main() -> int:
    output = run_scenarios()
    json_path, md_path = write_scenario_reports(output)
    print_cli_summary(output)
    print()
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    summary = output["summary"]
    return 0 if summary["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
