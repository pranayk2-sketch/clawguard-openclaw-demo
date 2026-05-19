# OpenClaw Dedicated ClawGuard Agent Setup

This guide explains how to create a **separate ClawGuard agent** in your local OpenClaw install. The repo ships an **example snippet only** — nothing here modifies `~/.openclaw/openclaw.json` automatically.

## Why a dedicated agent beats using `main`

| `main` agent | `clawguard` agent |
|--------------|-------------------|
| General assistant — broad tools | Security evaluator — narrow scope |
| May retain unrelated session context | Isolated `agentDir` / state |
| Higher blast radius if mis-prompted | Explicit workspace + exec allowlist |
| Harder to demo trust boundaries | Clear multi-agent architecture |

ClawGuard is designed as a **restricted harness evaluator**, not a replacement for your everyday agent.

## Prerequisites

- OpenClaw installed locally (`openclaw` on PATH)
- This repo cloned (demo workspace)
- No real API keys or tokens in the repo

## 1. Backup your config

```bash
cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.bak.$(date +%Y%m%d)
```

## 2. Inspect current config

```bash
openclaw doctor
cat ~/.openclaw/openclaw.json   # or your platform's config path
```

Note existing agents, gateway settings, and any `tools.exec` blocks.

## 3. Merge the ClawGuard snippet manually

1. Open `openclaw/clawguard-agent.example.json5` in this repo.
2. Copy the `clawguard` agent object into your `agents.list` array in `~/.openclaw/openclaw.json`.
3. Replace placeholders:
   - `CLAWGUARD_WORKSPACE_PATH` → absolute path to this repo  
     (e.g. `/Users/you/Desktop/clawguard-demo-workspace`)
   - `CLAWGUARD_AGENT_DIR` → e.g. `~/.openclaw/agents/clawguard`
4. Align tool allow/deny names with your OpenClaw version (comments in the example).
5. Ensure exec posture matches the demo:

```text
security=allowlist
ask=on-miss
askFallback=deny
```

**Do not** paste API keys, bot tokens, or personal credentials into the config.

## 4. Restart the gateway

Restart OpenClaw / the gateway the way your install documents (varies by version).

## 5. Verify

```bash
openclaw doctor
openclaw exec-policy show
openclaw approvals get
python scripts/verify_openclaw_posture.py
```

Expected posture signals: `security=allowlist`, `ask=on-miss`, `askFallback=deny`, and an allowlist section.

## 6. Run the live ClawGuard demo

Use prompts from `DEMO_SCRIPT.md` with the **clawguard** agent selected. Reference `CLAWGUARD_SYSTEM.md` in prompts.

Suggested flow:

1. Workspace audit → report under `reports/`
2. Refuse `~/.ssh` read
3. Refuse `rm -rf` / `curl`

## 7. Run deterministic harness checks

From the repo root:

```bash
python scripts/run_demo_checks.py
python scripts/scenario_runner.py
python scripts/harness_scorecard.py
python scripts/generate_audit_report.py
pytest
```

These prove scanner and scenario behavior **without** requiring OpenClaw.

## What is implemented vs manual

| Item | Status |
|------|--------|
| Example agent snippet | In repo (`openclaw/clawguard-agent.example.json5`) |
| Applying config to your machine | **Manual** (you merge + restart) |
| Python harness / scenarios | **Automated** in repo |
| Posture verifier | **Read-only** (`scripts/verify_openclaw_posture.py`) |

## Rollback

If anything breaks:

```bash
cp ~/.openclaw/openclaw.json.bak.YYYYMMDD ~/.openclaw/openclaw.json
# restart gateway
openclaw doctor
```

Restore the backup file you created in step 1. Re-run `openclaw exec-policy show` to confirm prior settings.

## Related docs

- `docs/THREAT_MODEL.md` — assets, boundaries, mitigations, gaps
- `docs/SRINI_FINAL_DEMO.md` — presentation flow
- `CLAWGUARD_SYSTEM.md` — agent policy text
