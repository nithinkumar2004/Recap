"""Pipeline Orchestrator: Drives the multi-agent release lifecycle state machine."""
from __future__ import annotations
import datetime
from typing import Optional, Callable

from app.models.contracts import (
    RepoSnapshot,
    ReleaseExecutionReport,
    CodeAnalysisResult,
    TestRunResult,
    SecurityScanResult,
    RiskEvaluation,
    ReleasePlanResult,
)
from app.agents.code_agent import CodeAgent
from app.agents.test_agent import TestAgent
from app.agents.security_agent import SecurityAgent
from app.core.risk_engine import RiskEngine
from app.agents.release_planner import ReleasePlannerAgent


class ReleaseOrchestrator:
    """Coordinates Code Agent, Test Agent, Security Agent, Risk Engine, and Planner Agent."""

    def __init__(
        self,
        code_agent: Optional[CodeAgent] = None,
        test_agent: Optional[TestAgent] = None,
        security_agent: Optional[SecurityAgent] = None,
        risk_engine: Optional[RiskEngine] = None,
        planner_agent: Optional[ReleasePlannerAgent] = None,
        event_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.code_agent = code_agent or CodeAgent()
        self.test_agent = test_agent or TestAgent()
        self.security_agent = security_agent or SecurityAgent()
        self.risk_engine = risk_engine or RiskEngine()
        self.planner_agent = planner_agent or ReleasePlannerAgent()
        self.event_callback = event_callback or (lambda phase, msg: None)

    def log_event(self, phase: str, msg: str):
        self.event_callback(phase, msg)

    def execute_pipeline(
        self,
        snapshot: RepoSnapshot,
        current_version: str = "v1.0.0",
        repo_dir: Optional[str] = None,
        precomputed_tests: Optional[TestRunResult] = None,
    ) -> ReleaseExecutionReport:
        """
        Executes the entire staged agent pipeline.
        Sequence:
        1. Code Agent
        2. Test Agent (or precomputed tests if simulated)
        3. Security Agent
        4. Risk Engine
        5. Release Planner
        """
        self.log_event("INITIALIZATION", f"Starting release evaluation for {snapshot.repository} (base: {snapshot.base_ref}, head: {snapshot.head_ref})")

        # Phase 1: Code Agent
        self.log_event("CODE_AGENT", "Analyzing commits, diffs, and AST signatures...")
        code_res = self.code_agent.analyze(snapshot, repo_dir=repo_dir)
        self.log_event("CODE_AGENT", f"Found {len(code_res.changes)} change(s), {len(code_res.breaking_changes)} breaking change(s). Bump: {code_res.suggested_bump.value}")

        # Phase 2: Test Agent
        self.log_event("TEST_AGENT", "Executing automated test suite...")
        if precomputed_tests is not None:
            test_res = precomputed_tests
        elif repo_dir is not None:
            test_res = self.test_agent.run(repo_dir)
        else:
            # Default empty / passing test result if no repo_dir is bound
            test_res = TestRunResult(framework="pytest", total=0, passed=0, failed=0, skipped=0, duration_seconds=0.0)
        if test_res.total == 0 and not test_res.execution_error and test_res.framework != "skipped":
            test_summary = "No tests discovered (0 tests run)"
        else:
            test_summary = f"Tests complete: {test_res.passed}/{test_res.total} passed, {test_res.failed} failed ({test_res.duration_seconds}s)"
        self.log_event("TEST_AGENT", test_summary)

        # Phase 3: Security Agent
        self.log_event("SECURITY_AGENT", "Running Gitleaks, Semgrep, and OSV vulnerability scanners...")
        security_res = self.security_agent.scan(snapshot)
        self.log_event("SECURITY_AGENT", f"Scans complete: {security_res.secrets_count} secret(s), {security_res.sast_high_count} SAST high, {security_res.dependency_critical_count} critical CVE(s)")

        # Phase 4: Risk Engine
        self.log_event("RISK_ENGINE", "Calculating weighted risk score and factor contributions...")
        risk_res = self.risk_engine.evaluate(snapshot, code_res, test_res, security_res)
        self.log_event("RISK_ENGINE", f"Risk Level: {risk_res.level.value} (Score: {risk_res.score}) with {len(risk_res.factors)} contributing factors")

        # Phase 5: Release Planner
        self.log_event("RELEASE_PLANNER", f"Synthesizing release proposal from {current_version}...")
        plan_res = self.planner_agent.plan(
            current_version=current_version,
            code_result=code_res,
            test_result=test_res,
            security_result=security_res,
            risk_result=risk_res,
        )
        self.log_event("RELEASE_PLANNER", f"Proposed version: {plan_res.proposed_version} (Recommendation: {plan_res.recommendation.value})")

        return ReleaseExecutionReport(
            repository=snapshot.repository,
            base_ref=snapshot.base_ref,
            head_ref=snapshot.head_ref,
            code_analysis=code_res,
            test_results=test_res,
            security_results=security_res,
            risk_evaluation=risk_res,
            release_plan=plan_res,
            analyzed_head_sha=snapshot.head_sha,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
