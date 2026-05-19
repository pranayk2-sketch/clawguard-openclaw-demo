# ClawGuard Threat Model

Concise threat model for the ClawGuard OpenClaw security demo and deterministic harness evaluator.

## Assets

| Asset | Why it matters |
|-------|----------------|
| User filesystem | Agents with shell/file tools can read or destroy data |
| SSH private keys (`~/.ssh`) | Full host/account compromise |
| API keys / tokens | Cloud spend, data breach, impersonation |
| Local repo contents | Source code, configs, fake/demo secrets |
| Agent session memory | Prior context may leak across tasks |
| Outbound channels | Email, chat, HTTP — data exfiltration |
| Shell execution | Arbitrary command running as the user |

## Trust boundaries

```text
[User prompt]
      │
      ▼
[OpenClaw agent policy]  ◄── CLAWGUARD_SYSTEM.md (clawguard agent)
      │
      ├── [Workspace documents]  ◄── untrusted (attacks/, repo_sample/)
      │
      ├── [Tool policy]  ◄── allow/deny per tool (version-specific names)
      │
      ├── [Exec approval layer]  ◄── allowlist + ask-on-miss + deny fallback
      │
      ├── [Sandbox / workspace boundary]  ◄── ro workspace, dedicated agentDir
      │
      └── [Network / messaging tools]  ◄── should be denied for ClawGuard
```

**Dedicated `clawguard` agent** vs **`main`**: separate trust boundary — ClawGuard must not inherit main’s broad permissions or memory.

## Threats

| ID | Threat | Example in this repo |
|----|--------|----------------------|
| T1 | Prompt injection in files | `attacks/prompt_injection.md`, `hidden_readme_instruction.md` |
| T2 | Secret exfiltration | `attacks/fake_env_file.env`, `base64_secret_prompt.md` |
| T3 | Destructive command execution | `rm -rf`, chmod, sudo |
| T4 | Workspace escape | `path_traversal_attempt.md`, `symlink_escape_notes.md` |
| T5 | Malicious package install | `package_install_attempt.md`, npm/pip/brew |
| T6 | Hidden instructions in README/docs | HTML comments in `hidden_readme_instruction.md` |
| T7 | Encoded / obfuscated leakage | `base64_secret_prompt.md` |
| T8 | Over-permissive main agent | Using `main` for security audits without isolation |
| T9 | Network exfiltration | `exfiltration_attempt.md`, curl/wget/scp/rsync |

## Mitigations (implemented in this repo)

| Mitigation | Layer |
|------------|--------|
| `CLAWGUARD_SYSTEM.md` policy | Agent instructions |
| Fake secrets only (no real credentials) | Repo design |
| `prompt_injection_scanner.py` | Deterministic harness |
| `secret_scanner.py` with redaction | Deterministic harness |
| `command_policy_checker.py` | Deterministic harness |
| `scenario_runner.py` + `harness_scorecard.py` | Scenario matrix + scoring |
| Exec allowlist + `ask=on-miss` + `askFallback=deny` | OpenClaw runtime (documented / local) |
| `openclaw/clawguard-agent.example.json5` | Dedicated agent profile example |
| `scripts/verify_openclaw_posture.py` | Read-only local posture check |

## Remaining gaps

- **OS/container sandbox verification** — example JSON5 documents intent; not proven here.
- **Tool-name enforcement** — exact OpenClaw tool IDs depend on local version/config.
- **Network egress monitor** — no real-time outbound traffic inspection in harness.
- **Policy-as-code inside OpenClaw** — no formal integration with OpenClaw internals yet.
- **Dedicated agent setup** — documented and manual unless user merges config locally.
- **Symlink probes** — described in scenarios, not filesystem-tested.
- **Harness does not execute shell** — classifies strings only; runtime may still differ if misconfigured.

## Recommended direction

1. Apply dedicated `clawguard` agent config locally (see `docs/OPENCLAW_AGENT_SETUP.md`).
2. CI: `pytest` + `scenario_runner.py` + optional `verify_openclaw_posture.py` on dev machines.
3. Production: kernel/container sandbox + egress firewall + agent trace scoring against scenario YAML.
