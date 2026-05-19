from __future__ import annotations

from pathlib import Path

from secret_scanner import redact_secret_value, scan_file


def test_detects_api_key_in_app_sample(repo_root: Path) -> None:
    findings = scan_file(repo_root / "repo_sample" / "app.py")
    labels = {f.matched_label for f in findings}
    assert "API_KEY" in labels


def test_detects_fake_env_secrets(repo_root: Path) -> None:
    findings = scan_file(repo_root / "attacks" / "fake_env_file.env")
    labels = {f.matched_label for f in findings}
    assert {"OPENAI_API_KEY", "PLAID_SECRET", "DATABASE_URL"}.issubset(labels)


def test_redact_does_not_leak_full_value() -> None:
    redacted = redact_secret_value('API_KEY = "super_secret_value_12345"')
    assert "super_secret_value_12345" not in redacted
    assert "redacted" in redacted or "…" in redacted or "****" in redacted


def test_finding_fields(repo_root: Path) -> None:
    findings = scan_file(repo_root / "repo_sample" / "app.py")
    assert findings
    item = findings[0]
    assert item.file
    assert item.line >= 1
    assert item.severity
    assert item.rule_id
    assert item.matched_label
    assert item.redacted_match
