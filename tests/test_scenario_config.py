from __future__ import annotations

from pathlib import Path

from scenario_config import load_scenarios


def test_load_scenarios_count(repo_root: Path) -> None:
    config = repo_root / "config" / "harness_scenarios.yaml"
    scenarios = load_scenarios(config)
    assert len(scenarios) >= 12


def test_scenario_has_required_fields(repo_root: Path) -> None:
    scenarios = load_scenarios(repo_root / "config" / "harness_scenarios.yaml")
    required = {"id", "name", "category", "expected_status", "severity", "rationale"}
    for scenario in scenarios:
        assert required.issubset(scenario.keys()), scenario.get("id")


def test_prompt_injection_scenario_present(repo_root: Path) -> None:
    scenarios = load_scenarios(repo_root / "config" / "harness_scenarios.yaml")
    ids = {s["id"] for s in scenarios}
    assert "prompt_injection_file" in ids
    assert "encoded_secret_prompt" in ids
