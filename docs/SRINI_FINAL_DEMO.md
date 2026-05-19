# ClawGuard Final Demo — Presentation Guide

## Problem statement

> Show quality of **agent harness** and **outcomes** using OpenClaw / Cowork-like tools.

Reviewers should leave believing you can design **trust boundaries**, measure safety **deterministically**, and operate a **restricted agent** — not just write a careful system prompt.

## What ClawGuard demonstrates

1. **Live OpenClaw workflow** — policy-bound audit, refusal of injection and unsafe exec  
2. **Deterministic harness evaluator** — 16-scenario matrix, scanners, scorecard, pytest  
3. **Multi-agent architecture** — dedicated `clawguard` profile vs general `main`  
4. **Threat model** — explicit assets, boundaries, mitigations, gaps  

## Why a dedicated agent matters

- **`main`** = general assistant (high privilege, broad memory)  
- **`clawguard`** = security harness evaluator (narrow workspace, exec allowlist, isolated state)  

Separating agents makes the **trust boundary** visible and demoable.

## 5-minute demo flow

### 1. Repo structure (30s)

- `CLAWGUARD_SYSTEM.md` — policy  
- `attacks/` — adversarial samples  
- `config/harness_scenarios.yaml` — scenario matrix  
- `openclaw/clawguard-agent.example.json5` — dedicated agent example  
- `scripts/` + `reports/`  

### 2. Policy (30s)

Open `CLAWGUARD_SYSTEM.md`: allowed workspace, blocked paths, injection rule, report format.

### 3. OpenClaw exec posture (45s)

```bash
openclaw exec-policy show
openclaw approvals get
python scripts/verify_openclaw_posture.py
```

Highlight: `security=allowlist`, `ask=on-miss`, `askFallback=deny`.

### 4. Live audit or cached report (60s)

Run Demo 1 from `DEMO_SCRIPT.md` **or** show `reports/initial_audit.md` / `generated_security_report.md`.

Call out: fake secrets, SQL pattern, prompt injection file.

### 5. Deterministic harness (60s)

```bash
python scripts/run_demo_checks.py
python scripts/scenario_runner.py
python scripts/harness_scorecard.py
```

Show `reports/scenario_results.md` and `reports/harness_scorecard.md` (target: 16/16 PASS).

### 6. Dedicated agent + threat model (45s)

- `openclaw/clawguard-agent.example.json5` — sandbox + exec blocklist (example only, manual merge)  
- `docs/THREAT_MODEL.md` — mitigations vs gaps  

### 7. Tests (30s, optional)

```bash
pytest -q
```

## Talking points

- **"This is not just prompt obedience."** Runtime exec policy and approvals enforce behavior even if the model drifts.  
- **"The deterministic harness mirrors expected safety."** Same attacks → same PASS/FAIL in CI.  
- **"The agent is designed around trust boundaries."** Dedicated profile, read-only workspace, isolated state.  
- **"Next production step: deeper sandboxing and network egress controls."** See threat model gaps.  

## Commands cheat sheet

```bash
python scripts/run_demo_checks.py
python scripts/scenario_runner.py
python scripts/harness_scorecard.py
python scripts/verify_openclaw_posture.py
python scripts/generate_audit_report.py
pytest
```

## Related docs

| Doc | Purpose |
|-----|---------|
| `DEMO_SCRIPT.md` | Live OpenClaw prompts |
| `docs/OPENCLAW_AGENT_SETUP.md` | Merge dedicated agent locally |
| `docs/THREAT_MODEL.md` | Security analysis |
| `docs/SRINI_DEMO.md` | Earlier internship walkthrough |
