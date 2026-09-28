"""Test Agent: Test framework detection, sandboxed execution, and normalized output parsing."""
from __future__ import annotations
import os
import re
from typing import Optional, List, Dict, Any, Tuple

from app.models.contracts import TestRunResult, TestCaseResult
from app.sandbox.runner import SandboxRunner


class TestAgent:
    """Agent responsible for running tests in an isolated sandbox and parsing results."""

    __test__ = False

    def __init__(self, runner: Optional[SandboxRunner] = None):
        self.runner = runner or SandboxRunner()

    def detect_framework(self, repo_dir: str) -> Tuple[str, str, str]:
        """
        Detects testing framework based on repository structure.
        Returns: (framework_name, command, docker_image)
        """
        # Node.js
        if os.path.exists(os.path.join(repo_dir, "package.json")):
            return "npm", "npm test -- --ci", "node:20-alpine"

        # Go
        if os.path.exists(os.path.join(repo_dir, "go.mod")):
            return "go", "go test -v ./...", "golang:1.22-alpine"

        # Rust
        if os.path.exists(os.path.join(repo_dir, "Cargo.toml")):
            return "cargo", "cargo test", "rust:1.77-slim"

        # Python default
        from app.config import settings
        return "pytest", "python -m pytest -v", settings.SANDBOX_PYTHON_BASE_IMAGE

    def run(self, repo_dir: str, custom_command: Optional[str] = None) -> TestRunResult:
        """Executes tests and returns standardized TestRunResult."""
        framework, default_command, image = self.detect_framework(repo_dir)
        command = custom_command or default_command

        exit_code, output, duration = self.runner.run_tests(
            repo_dir=repo_dir,
            command=command,
            image=image,
        )

        return self.parse_output(output, framework, duration, exit_code)

    def parse_output(self, output: str, framework: str, duration: float, exit_code: int) -> TestRunResult:
        """Parses output log based on framework syntax."""
        if framework == "pytest":
            return self._parse_pytest(output, duration, exit_code)
        elif framework == "npm":
            return self._parse_npm(output, duration, exit_code)
        else:
            return self._parse_generic(output, duration, exit_code, framework)

    def _parse_pytest(self, output: str, duration: float, exit_code: int) -> TestRunResult:
        passed = 0
        failed = 0
        skipped = 0

        # Pytest can report outcomes in different orders, e.g. "2 passed, 1 failed".
        summary_match = re.search(r"=+\s*(.*?)\s+in\s+([0-9.]+)s\s*=+", output, re.DOTALL)
        summary = summary_match.group(1) if summary_match else ""
        if summary_match:
            duration = float(summary_match.group(2))
            counts = {name: int(count) for count, name in re.findall(
                r"(\d+)\s+(passed|failed|skipped|error|xfailed|xpassed)", summary
            )}
            passed = counts.get("passed", 0) + counts.get("xpassed", 0)
            failed = counts.get("failed", 0) + counts.get("error", 0)
            skipped = counts.get("skipped", 0) + counts.get("xfailed", 0)
        else:
            passed = len(re.findall(r"\bPASSED\b", output))
            failed = len(re.findall(r"\b(?:FAILED|ERROR)\b", output))
            skipped = len(re.findall(r"\bSKIPPED\b", output))

        # Extract failed test names
        failures: List[TestCaseResult] = []
        fail_matches = re.findall(
            r"^(?:FAILED|ERROR)\s+([^\s]+)(?:\s+-\s*(.*))?$",
            output,
            re.MULTILINE,
        )
        for test_name, reason in fail_matches:
            if test_name == "collecting":
                continue
            failures.append(TestCaseResult(
                name=test_name.strip(),
                status="failed",
                error_message=reason.strip() if reason else "Assertion / Exception error"
            ))

        total = passed + failed + skipped
        # Runner/setup/collection errors are not test failures, but still block
        # publication because the test result could not be verified.
        collection_error = "ERROR collecting" in output or "ImportError while loading conftest" in output
        if collection_error and summary_match:
            failed = counts.get("failed", 0)
            total = passed + failed + skipped
        execution_error = None
        no_tests_collected = (
            exit_code == 5
            and total == 0
            and ("collected 0 items" in output or "no tests ran" in output.lower())
        )
        if exit_code != 0 and not no_tests_collected and (failed == 0 or collection_error):
            diagnostic_lines = [line.strip() for line in output.splitlines() if line.strip()]
            execution_error = "\n".join(diagnostic_lines[-12:]) or f"pytest exited with status {exit_code} without a test summary"

        return TestRunResult(
            framework="pytest",
            total=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            duration_seconds=round(duration, 2),
            failure_details=failures,
            execution_error=execution_error,
            diagnostics=output[-8000:] if exit_code != 0 else None,
        )

    def _parse_npm(self, output: str, duration: float, exit_code: int) -> TestRunResult:
        passed = len(re.findall(r"✓|PASS", output))
        failed = len(re.findall(r"✕|FAIL", output))
        skipped = len(re.findall(r"○|SKIPPED", output))
        total = passed + failed + skipped
        execution_error = (output[-4000:] or f"npm test exited with status {exit_code}") if exit_code != 0 and failed == 0 else None

        return TestRunResult(
            framework="npm",
            total=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            duration_seconds=round(duration, 2),
            failure_details=[],
            execution_error=execution_error,
            diagnostics=output[-8000:] if exit_code != 0 else None,
        )

    def _parse_generic(self, output: str, duration: float, exit_code: int, framework: str) -> TestRunResult:
        if exit_code == 0:
            return TestRunResult(framework=framework, total=1, passed=1, failed=0, skipped=0, duration_seconds=duration)
        else:
            return TestRunResult(
                framework=framework,
                total=1,
                passed=0,
                failed=1,
                skipped=0,
                duration_seconds=duration,
                failure_details=[TestCaseResult(name="generic_suite", status="failed", error_message="Non-zero exit code")]
            )
