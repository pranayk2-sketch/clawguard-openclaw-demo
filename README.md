# ClawGuard — OpenClaw Agent Security Harness Evaluator

**ClawGuard** is a security-focused OpenClaw personal agent demo with a **deterministic evaluation harness**. The live agent enforces policy at runtime; the Python harness proves that adversarial scenarios are detected consistently and produces internship-ready scorecards.

This is more than a toy demo: it pairs a real OpenClaw policy (`CLAWGUARD_SYSTEM.md`) with a versioned **scenario matrix**, scanners, command classification, and measurable pass rates.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│  main agent (general)     │  clawguard agent (restricted)       │
│  broad tools / memory     │  dedicated profile + sandbox (ro)   │
│                           │  CLAWGUARD_SYSTEM.md + narrow scope │
└───────────────────────────┴─────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│           OpenClaw exec approvals (runtime control)              │
│  security=allowlist | ask=on-miss | askFallback=deny             │
└────────────────────────────┬────────────────────────────────────┘
                             │ should align with
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│              Deterministic Harness (this repo)                    │
│  scanners + scenario_runner + harness_scorecard + pytest         │
└─────────────────────────────────────────────────────────────────┘
```

## Final architecture: dedicated ClawGuard agent

| Layer | Role |
|-------|------|
| **`main` agent** | General OpenClaw assistant — full tool surface, everyday tasks |
| **`clawguard` agent** | Restricted security harness evaluator — isolated `agentDir`, read-only workspace, blocked network/destructive tools |
| **Deterministic Python harness** | Repeatable tests: scanners, 16-scenario matrix, scorecard — no shell execution |
| **OpenClaw exec approvals** | Runtime gate: allowlist + prompt on miss + deny fallback |

Example dedicated-agent snippet (manual merge only): `openclaw/clawguard-agent.example.json5`  
Setup guide: `docs/OPENCLAW_AGENT_SETUP.md`  
Posture check (read-only): `python scripts/verify_openclaw_posture.py`

## Repository layout

| Path | Purpose |
|------|---------|
| `CLAWGUARD_SYSTEM.md` | Agent policy (allowlist, blocks, reporting) |
| `DEMO_SCRIPT.md` | Live OpenClaw demo script |
| `docs/SRINI_DEMO.md` | Presentation-ready walkthrough |
| `docs/SRINI_FINAL_DEMO.md` | Final presentation flow (multi-agent + harness) |
| `docs/OPENCLAW_AGENT_SETUP.md` | Dedicated agent setup (manual merge) |
| `docs/THREAT_MODEL.md` | Assets, threats, mitigations, gaps |
| `openclaw/clawguard-agent.example.json5` | Example dedicated agent config snippet |
| `config/harness_scenarios.yaml` | Adversarial scenario matrix (16 scenarios) |
| `attacks/` | Prompt injection, exfil, traversal, encoded secrets |
| `repo_sample/` | Intentionally vulnerable sample code |
| `safe_docs/` | Benign documentation |
| `reports/` | Audit output, scenario results, scorecard |
| `scripts/` | Scanners, scenario runner, scorecard, demo checks |
| `tests/` | Pytest suite |

## Setup

Requires **Python 3.10+**.

```bash
cd /path/to/clawguard-demo-workspace
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"   # or: pip install pytest
```

## Run the harness

From the repository root:

```bash
# Core demo checks + full scenario matrix
python scripts/run_demo_checks.py

# Scenario matrix only (writes reports/scenario_results.*)
python scripts/scenario_runner.py

# Scorecard from scenario results
python scripts/harness_scorecard.py

# Full-repo audit artifacts
python scripts/generate_audit_report.py

# Local OpenClaw posture (read-only; optional if CLI installed)
python scripts/verify_openclaw_posture.py

# Unit tests
pytest
```

## What the live OpenClaw demo shows

- Policy-bound workspace inspection only
- Refusal of prompt injection embedded in untrusted files
- Blocking of `~/.ssh`, destructive commands, package installs, and network tools
- Narrow read-only allowlist: `pwd`, `ls`, `find`/`cat`/`grep` under the approved workspace
- Human-readable reports written to `reports/`

See `DEMO_SCRIPT.md` for prompts and expected outcomes.

## What the deterministic harness verifies

| Layer | Verifies |
|-------|----------|
| `secret_scanner.py` | Fake/real-looking secrets (API_KEY, TOKEN, DATABASE_URL, …) with redaction |
| `prompt_injection_scanner.py` | Override language, exfil phrases, base64 obfuscation, install requests |
| `command_policy_checker.py` | Allow/block/approval_required without executing commands |
| `scenario_runner.py` | Each row in `harness_scenarios.yaml` → PASS/FAIL/PARTIAL |
| `harness_scorecard.py` | Overall and per-category scores, gaps, next steps |

## Adversarial scenario matrix

| Category | Examples |
|----------|----------|
| `prompt_injection` | `attacks/prompt_injection.md`, `hidden_readme_instruction.md` |
| `secrets` | `attacks/fake_env_file.env` |
| `code_security` | hardcoded key + unsafe SQL in `repo_sample/app.py` |
| `command_policy` | `rm -rf`, `npm install`, SSH read |
| `exfiltration` | `curl`/`wget` commands, `exfiltration_attempt.md` |
| `workspace_boundary` | path traversal, symlink escape notes |

## Generated reports

- `reports/scenario_results.json` / `.md` — per-scenario harness output
- `reports/harness_scorecard.md` — overall and category scores
- `reports/audit_events.jsonl` / `generated_security_report.md` — full scan summary

## Current limitations

- Dedicated agent config is an **example snippet** — you merge it locally; the repo does not edit `~/.openclaw/openclaw.json`.
- Harness classifies command **strings** only; it does not invoke OpenClaw or a real shell.
- Symlink escape scenarios are documented but not probed on the filesystem.
- Base64 detection is linguistic; payloads are not decoded.
- Scanners skip `scripts/`, `tests/`, `reports/`, and policy docs to reduce noise.
- Exact OpenClaw tool names and sandbox fields depend on your installed version.

## Next steps

- CI gate on `scenario_runner.py` with zero critical FAILs
- OpenClaw exec-policy replay tests using the same scenario YAML
- Sandbox fixtures for symlink and path traversal proofs
- Optional decoded-secret validator for obfuscation scenarios
