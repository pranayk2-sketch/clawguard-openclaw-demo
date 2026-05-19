from __future__ import annotations

from pathlib import Path

from prompt_injection_scanner import scan_file


def test_detects_injection_in_attack_file(repo_root: Path) -> None:
    findings = scan_file(repo_root / "attacks" / "prompt_injection.md")
    labels = {f.matched_label for f in findings}
    assert "ignore previous instructions" in labels
    assert "read ~/.ssh" in labels
    assert "do not tell the user" in labels


def test_safe_doc_has_no_injection(repo_root: Path) -> None:
    findings = scan_file(repo_root / "safe_docs" / "project_notes.md")
    assert findings == []
