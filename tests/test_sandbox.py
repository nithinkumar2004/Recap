"""Tests for sandbox fail-closed behavior."""
import pytest

from app.config import settings
from app.sandbox.runner import SandboxRunner


def test_missing_docker_does_not_execute_project_tests_on_host(tmp_path, monkeypatch):
    runner = SandboxRunner()
    runner.docker_client = None
    monkeypatch.setattr(settings, "SANDBOX_ALLOW_LOCAL_FALLBACK", False)

    def unexpected_local_execution(*args, **kwargs):
        pytest.fail("untrusted test command must not run on the host")

    runner._run_local_fallback = unexpected_local_execution
    exit_code, output, _ = runner.run_tests(str(tmp_path), command="touch SHOULD_NOT_RUN")

    assert exit_code == 125
    assert "Docker sandbox is unavailable" in output
    assert not (tmp_path / "SHOULD_NOT_RUN").exists()
