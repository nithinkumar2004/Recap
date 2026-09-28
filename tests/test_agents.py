"""Unit and integration tests for Release Captain agent suite."""
import pytest
from app.models.contracts import (
    RepoSnapshot,
    CommitInfo,
    FileDiff,
    VersionBump,
    RiskLevel,
    RiskEvaluation,
    Recommendation,
    TestRunResult,
    TestCaseResult,
    SecurityScanResult,
)
from app.agents.code_agent import CodeAgent, detect_ast_breaking_changes
from app.agents.security_agent import SecurityAgent
from app.agents.test_agent import TestAgent
from app.core.risk_engine import RiskEngine
from app.agents.release_planner import ReleasePlannerAgent, bump_semver
from app.core.orchestrator import ReleaseOrchestrator


def test_bump_semver():
    assert bump_semver("v1.2.3", VersionBump.PATCH) == "v1.2.4"
    assert bump_semver("v1.2.3", VersionBump.MINOR) == "v1.3.0"
    assert bump_semver("v1.2.3", VersionBump.MAJOR) == "v2.0.0"
    assert bump_semver("1.0.0", VersionBump.MINOR) == "1.1.0"


def test_code_agent_conventional_commits():
    agent = CodeAgent()
    
    # Minor bump test (feat)
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        commits=[
            CommitInfo(sha="abc1234", message="feat(auth): add google sso login"),
            CommitInfo(sha="def5678", message="fix(core): handle null pointer in session"),
        ]
    )
    result = agent.analyze(snapshot)
    assert result.suggested_bump == VersionBump.MINOR
    assert len(result.changes) == 2
    assert result.changes[0].type == "feat"

    # Major bump test (breaking commit)
    snapshot_major = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        commits=[
            CommitInfo(sha="1234567", message="feat!: change response payload schema"),
        ]
    )
    result_major = agent.analyze(snapshot_major)
    assert result_major.suggested_bump == VersionBump.MAJOR
    assert len(result_major.breaking_changes) > 0


def test_code_agent_ast_breaking_change():
    old_code = """
def fetch_user(user_id):
    return {"id": user_id}

class AccountService:
    def get_balance(self, account_id):
        return 100
"""
    new_code = """
def fetch_user(user_id, tenant_id):
    # Added required tenant_id parameter
    return {"id": user_id, "tenant": tenant_id}

class AccountService:
    def get_balance(self, account_id):
        return 100
"""
    breaking = detect_ast_breaking_changes(old_code, new_code, "src/services.py")
    assert len(breaking) == 1
    assert breaking[0].identifier == "fetch_user"
    assert "tenant_id" in breaking[0].impact


def test_code_agent_detects_positional_parameter_reordering():
    old_code = "def fetch_user(user_id, tenant_id):\n    pass\n"
    new_code = "def fetch_user(tenant_id, user_id):\n    pass\n"

    breaking = detect_ast_breaking_changes(old_code, new_code, "service.py")

    assert len(breaking) == 1
    assert "order" in breaking[0].impact


def test_code_agent_ignores_nested_local_functions():
    old_code = "def public_api(value):\n    def helper(a, b):\n        pass\n    return value\n"
    new_code = "def public_api(value):\n    def helper(a, b, required):\n        pass\n    return value\n"

    assert detect_ast_breaking_changes(old_code, new_code, "service.py") == []


def test_test_agent_distinguishes_runner_errors_from_test_failures():
    result = TestAgent().parse_output("sh: 1: pytest: not found", "pytest", 0.2, 127)

    assert result.total == 0
    assert result.failed == 0
    assert "pytest: not found" in result.execution_error
    assert "pytest: not found" in result.diagnostics


def test_test_agent_treats_pytest_no_tests_collected_as_no_tests_not_runner_error():
    output = "collected 0 items\n============================ no tests ran in 0.01s ============================="

    result = TestAgent().parse_output(output, "pytest", 0.01, 5)

    assert result.total == 0
    assert result.passed == 0
    assert result.failed == 0
    assert result.execution_error is None
    assert result.diagnostics == output


def test_test_agent_parses_pytest_summary_in_any_order():
    output = "=== 1 passed, 2 failed, 1 skipped in 0.45s ===\nFAILED test_api.py::test_bad - assertion failed"

    result = TestAgent().parse_output(output, "pytest", 1.0, 1)

    assert (result.passed, result.failed, result.skipped, result.total) == (1, 2, 1, 4)
    assert result.failure_details[0].name == "test_api.py::test_bad"


def test_test_agent_classifies_collection_errors_as_infrastructure_errors():
    output = "ERROR collecting tests/test_api.py\nImportError: missing dependency\n=== 1 error in 0.03s ==="

    result = TestAgent().parse_output(output, "pytest", 0.03, 2)

    assert result.failed == 0
    assert result.total == 0
    assert not result.failure_details
    assert "missing dependency" in result.execution_error


def test_security_agent_filters_false_positive_sources_and_fixed_dependencies():
    agent = SecurityAgent()
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        diffs=[
            FileDiff(filename="__pycache__/security_agent.pyc", patch="+cursor.execute(f\"SELECT {value}\")"),
            FileDiff(filename="app.py", patch="+# cursor.execute(f\"SELECT {value}\")"),
            FileDiff(filename="requirements.txt", patch="+requests==2.32.0\n"),
        ],
    )

    result = agent.scan(snapshot)

    assert result.findings == []
    assert result.sast_high_count == 0
    assert result.dependency_high_count == 0


def test_security_agent_reports_old_dependency_version():
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        diffs=[FileDiff(filename="requirements.txt", patch="+urllib3==2.0.6\n")],
    )

    result = SecurityAgent().scan(snapshot)

    assert result.dependency_high_count == 1
    assert any("CVE-2023-45803" in finding.title for finding in result.findings)


def test_risk_engine_ignores_generated_bytecode_as_auth_change():
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        changed_files=["app/agents/__pycache__/security_agent.cpython-314.pyc"],
    )
    code_result = CodeAgent().analyze(snapshot)

    risk_result = RiskEngine().evaluate(snapshot, code_result, TestRunResult(), SecurityScanResult())

    assert all(factor.name != "Authentication / Security Middleware Modified" for factor in risk_result.factors)


def test_security_agent_secret_detection():
    agent = SecurityAgent()
    patch = """@@ -1,3 +1,4 @@
+aws_key = 'AKIA1234567890ABCDEF'
+github_token = 'ghp_123456789012345678901234567890123456'
"""
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        diffs=[FileDiff(filename="config.py", patch=patch)]
    )
    result = agent.scan(snapshot)
    assert result.secrets_count == 2
    assert any("AWS Access Key" in f.title for f in result.findings)
    assert any("GitHub Personal Access Token" in f.title for f in result.findings)


def test_security_agent_sast_patterns():
    agent = SecurityAgent()
    patch = """@@ -10,3 +10,4 @@
+cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
+os.system(f"echo {user_input} | bash", shell=True)
"""
    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        diffs=[FileDiff(filename="db.py", patch=patch)]
    )
    result = agent.scan(snapshot)
    assert result.sast_high_count >= 2


def test_risk_engine_calculation():
    engine = RiskEngine()
    code_agent = CodeAgent()
    security_agent = SecurityAgent()

    snapshot = RepoSnapshot(
        repository="test/repo",
        base_ref="v1.0.0",
        head_ref="main",
        changed_files=["src/auth/jwt.py", "migrations/001_init.sql"],
        diffs=[
            FileDiff(
                filename="src/auth/jwt.py",
                additions=1200,
                deletions=50,
                patch="""@@ -1,2 +1,3 @@
+api_key = 'AKIAABCDEFGHIJKLMNOP'
"""
            ),
            FileDiff(filename="migrations/001_init.sql", additions=20, deletions=0)
        ]
    )

    code_res = code_agent.analyze(snapshot)
    security_res = security_agent.scan(snapshot)
    test_res = TestRunResult(total=10, passed=8, failed=2, skipped=0)

    risk_eval = engine.evaluate(snapshot, code_res, test_res, security_res)

    # Score breakdown:
    # +3 Auth, +3 Migration, +2 Large diff, +10 Test failures (2*5), +10 Secret
    assert risk_eval.score >= 25
    assert risk_eval.level == RiskLevel.CRITICAL
    assert len(risk_eval.factors) >= 4


def test_release_planner_blockers():
    planner = ReleasePlannerAgent()
    code_agent = CodeAgent()
    
    snapshot = RepoSnapshot(repository="test/repo", base_ref="v1.0.0", head_ref="main")
    code_res = code_agent.analyze(snapshot)
    
    # Case with test failures
    test_res = TestRunResult(total=50, passed=48, failed=2)
    security_res = SecurityScanResult()
    from app.core.risk_engine import RiskEvaluation, RiskLevel
    risk_eval = RiskEvaluation(score=10, level=RiskLevel.HIGH, factors=[])

    plan = planner.plan("v1.0.0", code_res, test_res, security_res, risk_eval)
    assert plan.recommendation == Recommendation.BLOCKED
    assert len(plan.blockers) > 0


def test_release_planner_blocks_unverified_test_execution_with_clear_reason():
    planner = ReleasePlannerAgent()
    code_res = CodeAgent().analyze(RepoSnapshot(repository="test/repo", base_ref="v1.0.0", head_ref="main"))
    test_res = TestRunResult(execution_error="pytest: not found")
    risk_eval = RiskEvaluation(score=5, level=RiskLevel.MEDIUM, factors=[])

    plan = planner.plan("v1.0.0", code_res, test_res, SecurityScanResult(), risk_eval)

    assert plan.recommendation == Recommendation.BLOCKED
    assert "could not be verified" in plan.blockers[0]


def test_release_planner_allows_approval_when_project_has_no_tests():
    planner = ReleasePlannerAgent()
    code_res = CodeAgent().analyze(RepoSnapshot(repository="test/repo", base_ref="v1.0.0", head_ref="main"))
    test_res = TestRunResult(total=0, passed=0, failed=0, framework="pytest")
    risk_eval = RiskEvaluation(score=0, level=RiskLevel.LOW, factors=[])

    plan = planner.plan("v1.0.0", code_res, test_res, SecurityScanResult(), risk_eval)

    assert plan.recommendation == Recommendation.APPROVAL_REQUIRED
    assert plan.blockers == []
    assert "No tests discovered (0 tests run)" in plan.release_notes_md


def test_orchestrator_pipeline_end_to_end():
    orchestrator = ReleaseOrchestrator()
    snapshot = RepoSnapshot(
        repository="org/demo-service",
        base_ref="v1.0.0",
        head_ref="main",
        commits=[
            CommitInfo(sha="c1", message="feat: add search endpoint"),
            CommitInfo(sha="c2", message="fix: fix search pagination"),
        ],
        changed_files=["src/search.py"],
        diffs=[FileDiff(filename="src/search.py", additions=45, deletions=5)]
    )

    test_res = TestRunResult(total=20, passed=20, failed=0, skipped=0, duration_seconds=2.5)

    report = orchestrator.execute_pipeline(
        snapshot=snapshot,
        current_version="v1.0.0",
        precomputed_tests=test_res,
    )

    assert report.repository == "org/demo-service"
    assert report.code_analysis.suggested_bump == VersionBump.MINOR
    assert report.release_plan.proposed_version == "v1.1.0"
    assert report.release_plan.recommendation == Recommendation.APPROVAL_REQUIRED
    assert report.risk_evaluation.level == RiskLevel.LOW
