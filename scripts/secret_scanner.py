#!/usr/bin/env python3
"""Scan files for fake or real-looking secrets using regex patterns."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

# (rule_id, label, pattern, severity)
SECRET_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "api_key_assignment",
        "API_KEY",
        re.compile(r"\bAPI_KEY\s*=\s*['\"]?[^\s'\"#]+", re.IGNORECASE),
        "high",
    ),
    (
        "openai_api_key",
        "OPENAI_API_KEY",
        re.compile(r"\bOPENAI_API_KEY\s*=\s*\S+", re.IGNORECASE),
        "high",
    ),
    (
        "plaid_secret",
        "PLAID_SECRET",
        re.compile(r"\bPLAID_SECRET\s*=\s*\S+", re.IGNORECASE),
        "high",
    ),
    (
        "database_url",
        "DATABASE_URL",
        re.compile(r"\bDATABASE_URL\s*=\s*\S+", re.IGNORECASE),
        "high",
    ),
    (
        "generic_secret",
        "SECRET",
        re.compile(r"\b[A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*\S+", re.IGNORECASE),
        "medium",
    ),
    (
        "generic_token",
        "TOKEN",
        re.compile(r"\b[A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*\S+", re.IGNORECASE),
        "medium",
    ),
    (
        "private_key_block",
        "PRIVATE KEY",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "critical",
    ),
]

SKIP_DIR_NAMES = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
SKIP_RELATIVE_PREFIXES = ("scripts/", "tests/", "reports/")
SKIP_FILE_NAMES = {"README.md", "generated_security_report.md"}
TEXT_EXTENSIONS = {
    ".py",
    ".md",
    ".env",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".sh",
    "",
}


@dataclass(frozen=True)
class SecretFinding:
    file: str
    line: int
    severity: str
    rule_id: str
    matched_label: str
    redacted_match: str


def redact_secret_value(text: str) -> str:
    """Replace likely secret values with a redacted placeholder."""
    if "=" in text:
        key, _, value = text.partition("=")
        value = value.strip()
        if len(value) <= 4:
            return f"{key.strip()}=****"
        return f"{key.strip()}={value[:2]}…{value[-2:]}(redacted)"
    if "PRIVATE KEY" in text:
        return "-----BEGIN … PRIVATE KEY----- (redacted)"
    return text[:8] + "…(redacted)" if len(text) > 8 else "****"


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
        suffix = path.suffix.lower()
        if suffix in TEXT_EXTENSIONS or path.name.endswith(".env"):
            yield path


def scan_file(path: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_no, line in enumerate(lines, start=1):
        for rule_id, label, pattern, severity in SECRET_RULES:
            match = pattern.search(line)
            if match:
                findings.append(
                    SecretFinding(
                        file=str(path),
                        line=line_no,
                        severity=severity,
                        rule_id=rule_id,
                        matched_label=label,
                        redacted_match=redact_secret_value(match.group(0)),
                    )
                )
    return findings


def scan_paths(paths: list[Path]) -> list[dict[str, object]]:
    """Scan explicit paths or directories and return structured findings."""
    all_findings: list[SecretFinding] = []
    for path in paths:
        if path.is_dir():
            for file_path in iter_scannable_files(path):
                all_findings.extend(scan_file(file_path))
        elif path.is_file():
            all_findings.extend(scan_file(path))
    return [asdict(f) for f in all_findings]


def scan_directory(root: Path) -> list[dict[str, object]]:
    return scan_paths([root])


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    findings = scan_directory(root)
    for item in findings:
        print(
            f"{item['file']}:{item['line']} "
            f"[{item['severity']}] {item['rule_id']} ({item['matched_label']}) "
            f"{item['redacted_match']}"
        )
    print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    main()
