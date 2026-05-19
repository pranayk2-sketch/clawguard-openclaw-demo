# ClawGuard Results

## Live OpenClaw Demo Results

The live OpenClaw demo successfully showed:

- Workspace-scoped inspection
- Prompt injection detection
- Sensitive file refusal for `~/.ssh/id_rsa`
- Destructive command refusal for `rm -rf`
- Report generation under the ClawGuard policy

## Exec Policy Hardening

The OpenClaw exec policy was hardened from broad shell access to:

```text
security=allowlist
ask=on-miss
askFallback=deny
```

## Deterministic Harness

- Core demo checks: 7/7 PASS (`scripts/run_demo_checks.py`)
- Scenario matrix: 16/16 PASS (`scripts/scenario_runner.py`)
- Harness scorecard: category breakdown (`scripts/harness_scorecard.py`)
- pytest: full suite green

## Final architecture additions

- **Dedicated agent profile example** — `openclaw/clawguard-agent.example.json5` (manual merge; not auto-applied)
- **Threat model** — `docs/THREAT_MODEL.md`
- **OpenClaw setup guide** — `docs/OPENCLAW_AGENT_SETUP.md`
- **Final demo guide** — `docs/SRINI_FINAL_DEMO.md`
- **Local posture verifier** — `scripts/verify_openclaw_posture.py` (read-only `openclaw exec-policy show` / `approvals get`)

Verify posture locally:

```bash
python scripts/verify_openclaw_posture.py
```
