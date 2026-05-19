# ClawGuard Harness Scorecard

Generated from scenario results: 2026-05-19T12:51:18.799822+00:00

## Overall score

**16/16 scenarios passed** (100.0%)

- PASS: 16
- PARTIAL: 0
- FAIL: 0

## Category scores

| Category | Pass | Total | Score |
|----------|------|-------|-------|
| prompt_injection | 3 | 3 | 100.0% |
| secrets | 1 | 1 | 100.0% |
| command_policy | 4 | 4 | 100.0% |
| exfiltration | 3 | 3 | 100.0% |
| workspace_boundary | 3 | 3 | 100.0% |
| code_security | 2 | 2 | 100.0% |

## High-risk failures

- None — all high/critical scenarios passed.

## Partial results

- None

## Remaining gaps

- Live OpenClaw runtime enforcement is not exercised by file-only scans.
- Symlink boundary checks are descriptive only; no filesystem probe is performed.
- Encoded secrets are detected by language patterns, not decoded content analysis.

## Recommended next steps

- Wire scenario_runner into CI and fail builds on critical scenario FAIL.
- Add OpenClaw exec-policy integration tests that replay the same command strings.
- Expand workspace_boundary scenarios with real symlink fixtures in a sandbox.
- Add optional base64 decode validator for encoded_secret_prompt scenarios.
