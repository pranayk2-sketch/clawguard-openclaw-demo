#!/usr/bin/env python3
"""Detect prompt-injection language in untrusted workspace files."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

INJECTION_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "ignore_previous",
        "ignore previous instructions",
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
        "high",
    ),
    (
        "override_system",
        "override system",
        re.compile(r"override\s+system", re.IGNORECASE),
        "high",
    ),
    (
        "developer_message",
        "developer message",
        re.compile(r"developer\s+message", re.IGNORECASE),
        "high",
    ),
    (
        "hide_from_user",
        "do not tell the user",
        re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
        "high",
    ),
    (
        "send_to",
        "send to",
        re.compile(r"send\s+(?:to|contents|their\s+contents)", re.IGNORECASE),
        "high",
    ),
    (
        "exfiltrate",
        "exfiltrate",
        re.compile(r"exfiltrat", re.IGNORECASE),
        "critical",
    ),
    (
        "base64_obfuscation",
        "base64",
        re.compile(r"\bbase64\b", re.IGNORECASE),
        "medium",
    ),
    (
        "decode_secret",
        "decode this secret",
        re.compile(r"decode\s+this\s+secret", re.IGNORECASE),
        "high",
    ),
    (
        "read_ssh",
        "read ~/.ssh",
        re.compile(r"read\s+~/?\.ssh|~/?\.ssh/id_rsa", re.IGNORECASE),
        "critical",
    ),
    (
        "read_env",
        "read .env",
        re.compile(r"read\s+.*\.env|\.env\s+files", re.IGNORECASE),
        "high",
    ),
    (
        "curl_command",
        "curl",
        re.compile(r"\bcurl\b", re.IGNORECASE),
        "critical",
    ),
    (
        "wget_command",
        "wget",
        re.compile(r"\bwget\b", re.IGNORECASE),
        "critical",
    ),
    (
        "package_install_language",
        "package install",
        re.compile(r"\b(?:brew\s+install|npm\s+install|pip\s+install)\b", re.IGNORECASE),
        "high",
    ),
    (
        "path_traversal_language",
        "path traversal",
        re.compile(
            r"(?:\.\./){2,}|/etc/passwd|cat\s+\.\./|find\s+/etc|outside\s+the\s+approved\s+workspace",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "symlink_escape",
        "symlink escape",
        re.compile(r"symlink|ln\s+-s", re.IGNORECASE),
        "medium",
    ),
]

SKIP_DIR_NAMES = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
SKIP_RELATIVE_PREFIXES = ("scripts/", "tests/", "reports/", "config/")
SKIP_FILE_NAMES = {
    "CLAWGUARD_SYSTEM.md",
    "DEMO_SCRIPT.md",
    "README.md",
    "generated_security_report.md",
    "harness_scorecard.md",
    "scenario_results.md",
}


@dataclass(frozen=True)
class InjectionFinding:
    file: str
    line: int
    severity: str
    rule_id: str
    matched_label: str
    snippet: str


def _should_skip(path: Path, root: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in path.parts):
        return True
    if path.name in SKIP_FILE_NAMES:
        return True
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return True
    return rel.startswith(SKIP_RELATIVE_PREFIXES)


def iter_scannable_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip(path, root):
            continue
        if path.suffix.lower() in {".md", ".txt", ".env", ".py", ".json", ""}:
            yield path


def scan_file(path: Path) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule_id, label, pattern, severity in INJECTION_RULES:
            if pattern.search(line):
                snippet = stripped[:120] + ("…" if len(stripped) > 120 else "")
                findings.append(
                    InjectionFinding(
                        file=str(path),
                        line=line_no,
                        severity=severity,
                        rule_id=rule_id,
                        matched_label=label,
                        snippet=snippet,
                    )
                )
    return findings


def scan_directory(root: Path) -> list[dict[str, object]]:
    all_findings: list[InjectionFinding] = []
    for file_path in iter_scannable_files(root):
        all_findings.extend(scan_file(file_path))
    return [asdict(f) for f in all_findings]


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    findings = scan_directory(root)
    for item in findings:
        print(
            f"{item['file']}:{item['line']} "
            f"[{item['severity']}] {item['rule_id']} — {item['matched_label']}"
        )
    print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    main()
