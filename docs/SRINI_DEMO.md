# ClawGuard — Internship Demo Guide

## Problem statement

OpenClaw-style agents can read files, run shell commands, and write reports. That power is useful for security auditing—but the same tools enable **prompt injection**, **secret leakage**, **destructive commands**, and **network exfiltration** if policy is weak or missing.

## Why OpenClaw agents need harness security

Live policy (`CLAWGUARD_SYSTEM.md`) protects one session. A **harness** proves protection is **repeatable**:

- Same adversarial inputs → same expected outcomes
- Measurable pass rate across categories
- Evidence for reviewers (JSON + Markdown scorecards)

Without a harness, demos rely on luck: the agent might refuse an attack once but miss it on the next run.

## What ClawGuard does

1. **Live agent (OpenClaw):** ClawGuard inspects only the approved workspace, treats files as untrusted data, blocks dangerous exec, and writes reports under `reports/`.
2. **Deterministic harness (Python):** Mirrors those guarantees with scanners and a 16-scenario matrix—no shell execution, no real secrets.

## Live demo (5 minutes)

1. Show `CLAWGUARD_SYSTEM.md` — allowed vs blocked behavior.
2. Run **Demo 1** from `DEMO_SCRIPT.md` — workspace audit → `reports/initial_audit.md`.
3. Point at findings: `attacks/prompt_injection.md`, `attacks/fake_env_file.env`, `repo_sample/app.py`.
4. Run **Demo 2** — direct request to read `~/.ssh` → refusal.
5. Run **Demo 3** — `rm -rf` or `curl` → blocked by exec policy.

**Pitch line:** *ClawGuard does useful security work inside a sandbox, and refuses everything else.*

## Deterministic checks (2 minutes)

```bash
python scripts/run_demo_checks.py
python scripts/scenario_runner.py
python scripts/harness_scorecard.py
```

Show `reports/scenario_results.md` and `reports/harness_scorecard.md`.

## What the scorecard means

| Field | Meaning |
|-------|---------|
| **Overall score** | PASS scenarios ÷ total (target: 100% on critical rows) |
| **Category scores** | prompt_injection, secrets, command_policy, exfiltration, workspace_boundary, code_security |
| **High-risk failures** | Critical/high severity scenarios that FAIL — must be zero before shipping |
| **Remaining gaps** | Known limitations (no live OpenClaw replay, no symlink probe) |
| **Next steps** | Concrete harness roadmap |

## Why this is more than a toy demo

- **Versioned scenario matrix** (`config/harness_scenarios.yaml`) — auditable adversarial catalog
- **Six attack themes** in `attacks/` — exfil, hidden instructions, installs, encoding, traversal, symlinks
- **Structured outputs** — JSON for CI, Markdown for humans
- **Tests** — `pytest` locks behavior across changes

## What I would improve next (company harness)

1. **CI integration** — fail builds when critical scenarios FAIL.
2. **OpenClaw replay** — feed the same YAML commands into exec-policy integration tests.
3. **Filesystem fixtures** — real symlink and traversal proofs in an isolated sandbox.
4. **Agent trace scoring** — compare live agent transcripts to harness expectations (did it refuse? did it leak?).
5. **Coverage expansion** — MCP tool abuse, outbound webhooks, multi-turn injection chains.

## Quick reference

| Artifact | Path |
|----------|------|
| Agent policy | `CLAWGUARD_SYSTEM.md` |
| Live script | `DEMO_SCRIPT.md` |
| Scenarios | `config/harness_scenarios.yaml` |
| Scenario results | `reports/scenario_results.md` |
| Scorecard | `reports/harness_scorecard.md` |
