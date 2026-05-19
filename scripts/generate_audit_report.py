#!/usr/bin/env python3
"""Run security scanners and write structured audit artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from command_policy_checker import classify_command
from prompt_injection_scanner import scan_directory as scan_injections
from secret_scanner import scan_directory as scan_secrets
from workspace import get_approved_workspace_prefix, get_repo_root


def _event(event_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        **payload,
    }


def collect_command_samples() -> list[dict[str, object]]:
    prefix = get_approved_workspace_prefix()
    samples = [
        "pwd",
        f"find {prefix} -name '*.py'",
        f"cat {prefix}/repo_sample/app.py",
        f"grep -r API_KEY {prefix}",
        "rm -rf /tmp/demo",
        "cat ~/.ssh/id_rsa",
    ]
    return [
        _event("command_classification", {"command": cmd, **classify_command(cmd)})
        for cmd in samples
    ]


def build_markdown_summary(
    secrets: list[dict[str, object]],
    injections: list[dict[str, object]],
    commands: list[dict[str, object]],
) -> str:
    lines = [
        "# ClawGuard Generated Security Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        f"- Secret-pattern findings: **{len(secrets)}**",
        f"- Prompt-injection findings: **{len(injections)}**",
        f"- Command policy samples: **{len(commands)}**",
        "",
        "## Secret scan highlights",
        "",
    ]
    if secrets:
        for item in secrets[:15]:
            lines.append(
                f"- `{item['file']}:{item['line']}` "
                f"[{item['severity']}] **{item['matched_label']}** "
                f"({item['rule_id']}) — `{item['redacted_match']}`"
            )
        if len(secrets) > 15:
            lines.append(f"- … and {len(secrets) - 15} more")
    else:
        lines.append("- No secret-pattern matches.")

    lines.extend(["", "## Prompt injection highlights", ""])
    if injections:
        for item in injections[:15]:
            lines.append(
                f"- `{item['file']}:{item['line']}` "
                f"[{item['severity']}] **{item['matched_label']}** — {item['snippet']}"
            )
        if len(injections) > 15:
            lines.append(f"- … and {len(injections) - 15} more")
    else:
        lines.append("- No injection-language matches.")

    lines.extend(["", "## Command policy samples", ""])
    for item in commands:
        cmd = item.get("command", "")
        status = item.get("status", "")
        reason = item.get("reason", "")
        lines.append(f"- `{cmd}` → **{status}** ({reason})")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "This report was produced by the deterministic ClawGuard evaluation harness.",
            "Values that resemble secrets are redacted in scanner output.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_reports(root: Path | None = None) -> tuple[Path, Path]:
    repo = root or get_repo_root()
    reports_dir = repo / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    secrets = scan_secrets(repo)
    injections = scan_injections(repo)
    commands = collect_command_samples()

    events: list[dict[str, object]] = []
    for finding in secrets:
        events.append(_event("secret_finding", finding))
    for finding in injections:
        events.append(_event("injection_finding", finding))
    events.extend(commands)

    jsonl_path = reports_dir / "audit_events.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    md_path = reports_dir / "generated_security_report.md"
    md_path.write_text(
        build_markdown_summary(secrets, injections, commands),
        encoding="utf-8",
    )
    return jsonl_path, md_path


def main() -> None:
    jsonl_path, md_path = generate_reports()
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
