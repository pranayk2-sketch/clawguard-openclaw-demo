from __future__ import annotations

from verify_openclaw_posture import (
    REQUIRED_CHECKS,
    evaluate_output,
    verify_posture,
)


def _mock_runner_factory(exec_out: str, appr_out: str, code: int = 0):
    def runner(args: list[str]) -> tuple[int, str, str]:
        if "exec-policy" in args:
            return code, exec_out, exec_out
        return code, appr_out, appr_out

    return runner


def test_evaluate_output_detects_allowlist() -> None:
    text = "security=allowlist\nask=on-miss\naskFallback=deny\nAllowlist: pwd, ls"
    results = evaluate_output(text, REQUIRED_CHECKS)
    assert all(ok for _, ok in results)


def test_verify_posture_pass_with_mocked_cli() -> None:
    combined = """
    security=allowlist
    ask=on-miss
    askFallback=deny
    Allowlist:
      - pwd
      - ls
    """
    result = verify_posture(_mock_runner_factory(combined, combined))
    assert result["openclaw_installed"] is True
    assert result["all_required_pass"] is True
    assert result["exit_code"] == 0


def test_verify_posture_fail_missing_deny_fallback() -> None:
    combined = "security=allowlist\nask=on-miss\nAllowlist: pwd"
    result = verify_posture(_mock_runner_factory(combined, combined))
    assert result["all_required_pass"] is False
    assert result["exit_code"] == 1


def test_verify_posture_not_installed(monkeypatch) -> None:
    monkeypatch.setattr("verify_openclaw_posture.openclaw_available", lambda: False)
    result = verify_posture()
    assert result["openclaw_installed"] is False
    assert result["exit_code"] == 0
