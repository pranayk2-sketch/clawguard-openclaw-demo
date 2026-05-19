"""Load harness scenario definitions from config/harness_scenarios.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from workspace import get_repo_root


def load_scenarios(config_path: Path | None = None) -> list[dict[str, str]]:
    """
    Parse the simple YAML scenario matrix (scalars only, no nesting).

    Avoids external dependencies while supporting the project's config format.
    """
    path = config_path or (get_repo_root() / "config" / "harness_scenarios.yaml")
    text = path.read_text(encoding="utf-8")
    scenarios: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "scenarios:":
            continue
        if line.startswith("- id:"):
            if current:
                scenarios.append(current)
            current = {"id": line.split(":", 1)[1].strip()}
            continue
        if current is not None and ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()

    if current:
        scenarios.append(current)
    return scenarios


def get_scenario_by_id(scenario_id: str, config_path: Path | None = None) -> dict[str, str] | None:
    for scenario in load_scenarios(config_path):
        if scenario.get("id") == scenario_id:
            return scenario
    return None
