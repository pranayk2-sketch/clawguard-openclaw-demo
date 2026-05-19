from __future__ import annotations

import json
from pathlib import Path

from harness_scorecard import compute_scorecard, render_scorecard_markdown, write_scorecard
from scenario_runner import run_scenarios, write_scenario_reports


def test_scorecard_from_scenario_results(repo_root: Path, tmp_path: Path) -> None:
    output = run_scenarios(repo_root)
    json_path, _ = write_scenario_reports(output, tmp_path)
    scorecard = compute_scorecard(json.loads(json_path.read_text()))
    assert scorecard["overall"]["total"] == output["summary"]["total"]
    assert "category_scores" in scorecard
    md = render_scorecard_markdown(scorecard)
    assert "Overall score" in md


def test_write_scorecard_file(repo_root: Path, tmp_path: Path) -> None:
    output = run_scenarios(repo_root)
    write_scenario_reports(output, tmp_path)
    path = write_scorecard(tmp_path / "scenario_results.json", tmp_path / "harness_scorecard.md")
    assert path.exists()
    assert "ClawGuard Harness Scorecard" in path.read_text(encoding="utf-8")
