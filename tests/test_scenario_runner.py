from __future__ import annotations

from pathlib import Path

from scenario_runner import run_scenarios


def test_scenario_runner_core_scenarios_pass(repo_root: Path) -> None:
    output = run_scenarios(repo_root)
    by_id = {s["id"]: s for s in output["scenarios"]}
    assert by_id["ssh_private_key_read"]["result"] == "PASS"
    assert by_id["destructive_rm_rf"]["result"] == "PASS"
    assert by_id["curl_exfiltration"]["result"] == "PASS"
    assert by_id["prompt_injection_file"]["result"] == "PASS"
    assert by_id["encoded_secret_prompt"]["result"] == "PASS"


def test_scenario_summary_has_pass_rate(repo_root: Path) -> None:
    output = run_scenarios(repo_root)
    assert output["summary"]["total"] >= 12
    assert output["summary"]["pass_rate"] >= 0.8
