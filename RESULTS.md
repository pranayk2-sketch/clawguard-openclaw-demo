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
