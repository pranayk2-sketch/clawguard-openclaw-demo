# ClawGuard Demo Workspace

A security-focused OpenClaw agent demo: **ClawGuard** inspects an approved workspace, resists prompt injection, blocks unsafe shell commands, and produces audit reports—without accessing private files or leaking secrets.

## Repository layout

| Path | Purpose |
|------|---------|
| `CLAWGUARD_SYSTEM.md` | Agent policy (allowlist, blocks, reporting rules) |
| `DEMO_SCRIPT.md` | Live demo script and expected outcomes |
| `attacks/` | Adversarial samples (prompt injection, fake `.env`) |
| `repo_sample/` | Intentionally vulnerable sample app |
| `safe_docs/` | Benign documentation |
| `reports/` | Human and machine-readable audit output |
| `scripts/` | Deterministic scanners and demo checks |
| `tests/` | Pytest suite for the harness |

## Setup

Requires **Python 3.10+**.

```bash
cd /path/to/clawguard-demo-workspace

# Optional: create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install pytest for development
pip install -e ".[dev]"
# Or minimal install:
pip install pytest
```

## Run the evaluation harness

From the repository root:

```bash
# Demo PASS/FAIL checks (prompt injection, secrets, SQL, command policy)
python scripts/run_demo_checks.py

# Generate audit artifacts under reports/
python scripts/generate_audit_report.py

# Unit tests
pytest
```

Individual scanners (optional):

```bash
python scripts/secret_scanner.py
python scripts/prompt_injection_scanner.py
python scripts/command_policy_checker.py "pwd" "rm -rf /tmp"
```

## Generated reports

- `reports/audit_events.jsonl` — structured events (secrets, injections, command samples)
- `reports/generated_security_report.md` — human-readable summary

Existing demo reports (`reports/initial_audit.md`, etc.) are preserved.

## Live agent demo

Use `DEMO_SCRIPT.md` with an OpenClaw agent configured using `CLAWGUARD_SYSTEM.md`. The Python harness mirrors what the live demo should find; it does not replace policy enforcement in the agent runtime.

## Design notes

- Scanners use regex only; no network calls and no execution of classified commands.
- Secret values are redacted in all scanner output.
- Command policy classifies strings only (`allowed` / `blocked` / `approval_required`).
