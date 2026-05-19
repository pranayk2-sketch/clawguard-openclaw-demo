#!/usr/bin/env python3
"""Build a harness scorecard from scenario matrix results."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from workspace import get_repo_root

CATEGORY_ORDER = [
    "prompt_injection",
    "secrets",
    "command_policy",
    "exfiltration",
    "workspace_boundary",
    "code_security",
]


def load_scenario_results(path: Path | None = None) -> dict[str, object]:
    results_path = path or (get_repo_root() / "reports" / "scenario_results.json")
    return json.loads(results_path.read_text(encoding="utf-8"))


def compute_scorecard(data: dict[str, object]) -> dict[str, object]:
    scenarios = data.get("scenarios", [])
    by_category: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in scenarios:
        by_category[str(item.get("category", "unknown"))].append(item)  # type: ignore[arg-type]

    category_scores: dict[str, dict[str, object]] = {}
    for category in CATEGORY_ORDER:
        items = by_category.get(category, [])
        if not items:
            continue
        passed = sum(1 for i in items if i.get("result") == "PASS")
        category_scores[category] = {
            "total": len(items),
            "pass": passed,
            "partial": sum(1 for i in items if i.get("result") == "PARTIAL"),
            "fail": sum(1 for i in items if i.get("result") == "FAIL"),
            "score": round(passed / len(items), 3) if items else 0.0,
        }

    summary = data.get("summary", {})
    high_risk_failures = [
        s
        for s in scenarios  # type: ignore[union-attr]
        if s.get("result") == "FAIL" and s.get("severity") in {"critical", "high"}
    ]
    partial_items = [s for s in scenarios if s.get("result") == "PARTIAL"]  # type: ignore[union-attr]

    gaps = _remaining_gaps(scenarios, partial_items, high_risk_failures)  # type: ignore[arg-type]
    next_steps = _recommended_next_steps(gaps)

    return {
        "generated_at": data.get("generated_at"),
        "overall": {
            "total": summary.get("total", 0),
            "pass": summary.get("pass", 0),
            "partial": summary.get("partial", 0),
            "fail": summary.get("fail", 0),
            "score": summary.get("pass_rate", 0.0),
        },
        "category_scores": category_scores,
        "high_risk_failures": high_risk_failures,
        "partial_results": partial_items,
        "remaining_gaps": gaps,
        "recommended_next_steps": next_steps,
    }


def _remaining_gaps(
    scenarios: list[dict[str, object]],
    partial: list[dict[str, object]],
    failures: list[dict[str, object]],
) -> list[str]:
    gaps: list[str] = []
    if failures:
        ids = ", ".join(str(f.get("id")) for f in failures)
        gaps.append(f"Failed scenarios need harness or policy fixes: {ids}")
    if partial:
        gaps.append(
            f"{len(partial)} scenario(s) only partially met expectations (e.g. detected but weak signals)."
        )
    categories = {s.get("category") for s in scenarios}
    if "exfiltration" in categories:
        gaps.append("Live OpenClaw runtime enforcement is not exercised by file-only scans.")
    gaps.append("Symlink boundary checks are descriptive only; no filesystem probe is performed.")
    gaps.append("Encoded secrets are detected by language patterns, not decoded content analysis.")
    return gaps


def _recommended_next_steps(gaps: list[str]) -> list[str]:
    steps = [
        "Wire scenario_runner into CI and fail builds on critical scenario FAIL.",
        "Add OpenClaw exec-policy integration tests that replay the same command strings.",
        "Expand workspace_boundary scenarios with real symlink fixtures in a sandbox.",
        "Add optional base64 decode validator for encoded_secret_prompt scenarios.",
    ]
    if any("Failed scenarios" in g for g in gaps):
        steps.insert(0, "Fix failing scenarios before expanding the matrix.")
    return steps


def render_scorecard_markdown(scorecard: dict[str, object]) -> str:
    overall = scorecard["overall"]
    lines = [
        "# ClawGuard Harness Scorecard",
        "",
        f"Generated from scenario results: {scorecard.get('generated_at', 'n/a')}",
        "",
        "## Overall score",
        "",
        f"**{overall['pass']}/{overall['total']} scenarios passed** "
        f"({overall['score']:.1%})",
        "",
        f"- PASS: {overall['pass']}",
        f"- PARTIAL: {overall['partial']}",
        f"- FAIL: {overall['fail']}",
        "",
        "## Category scores",
        "",
        "| Category | Pass | Total | Score |",
        "|----------|------|-------|-------|",
    ]
    for category, stats in scorecard["category_scores"].items():
        lines.append(
            f"| {category} | {stats['pass']} | {stats['total']} | {stats['score']:.1%} |"
        )

    lines.extend(["", "## High-risk failures", ""])
    if scorecard["high_risk_failures"]:
        for item in scorecard["high_risk_failures"]:
            lines.append(
                f"- **{item['id']}** ({item['severity']}): expected "
                f"{item['expected_status']}, got {item['actual_status']}"
            )
    else:
        lines.append("- None — all high/critical scenarios passed.")

    lines.extend(["", "## Partial results", ""])
    if scorecard["partial_results"]:
        for item in scorecard["partial_results"]:
            lines.append(f"- {item['id']}: {item.get('details', '')}")
    else:
        lines.append("- None")

    lines.extend(["", "## Remaining gaps", ""])
    for gap in scorecard["remaining_gaps"]:
        lines.append(f"- {gap}")

    lines.extend(["", "## Recommended next steps", ""])
    for step in scorecard["recommended_next_steps"]:
        lines.append(f"- {step}")

    lines.append("")
    return "\n".join(lines)


def write_scorecard(
    results_path: Path | None = None, output_path: Path | None = None
) -> Path:
    data = load_scenario_results(results_path)
    scorecard = compute_scorecard(data)
    path = output_path or (get_repo_root() / "reports" / "harness_scorecard.md")
    path.write_text(render_scorecard_markdown(scorecard), encoding="utf-8")
    return path


def main() -> None:
    path = write_scorecard()
    data = load_scenario_results()
    overall = compute_scorecard(data)["overall"]
    print("ClawGuard Harness Scorecard")
    print(f"Overall: {overall['pass']}/{overall['total']} ({overall['score']:.1%})")
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
