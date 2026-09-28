"""Tests for Release Executor, HEAD integrity, and audit logging."""
import pytest
import os
import subprocess
from app.models.contracts import (
    RepoSnapshot,
    CommitInfo,
    FileDiff,
    TestRunResult,
    SecurityScanResult,
    RiskEvaluation,
    ReleasePlanResult,
    ReleaseExecutionReport,
    VersionBump,
    RiskLevel,
    Recommendation,
    CodeAnalysisResult,
)
from app.release.executor import ReleaseExecutor


def create_dummy_report(blockers=None):
    return ReleaseExecutionReport(
        repository="myorg/test-service",
        base_ref="v1.0.0",
        head_ref="sha_initial_123",
        code_analysis=CodeAnalysisResult(
            changes=[],
            breaking_changes=[],
            suggested_bump=VersionBump.PATCH,
            reason="Patch fix",
        ),
        test_results=TestRunResult(total=10, passed=10, failed=0),
        security_results=SecurityScanResult(),
        risk_evaluation=RiskEvaluation(score=2, level=RiskLevel.LOW, factors=[]),
        release_plan=ReleasePlanResult(
            current_version="v1.0.0",
            proposed_version="v1.0.1",
            bump_type=VersionBump.PATCH,
            risk_level=RiskLevel.LOW,
            risk_score=2,
            release_notes_md="# Release v1.0.1\n- Bug fix",
            recommendation=Recommendation.APPROVAL_REQUIRED if not blockers else Recommendation.BLOCKED,
            blockers=blockers or [],
        ),
        analyzed_head_sha="sha_initial_123",
    )


def create_git_repo(repo_dir):
    subprocess.run(["git", "init", "-q", str(repo_dir)], check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    (repo_dir / "README.md").write_text("test repository\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "chore: initialize"], cwd=repo_dir, check=True, capture_output=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_executor_approve_and_rollback_real_local_release(tmp_path):
    head_sha = create_git_repo(tmp_path)
    executor = ReleaseExecutor()
    report = create_dummy_report().model_copy(update={"analyzed_head_sha": head_sha})

    res = executor.execute(
        report=report,
        decision="APPROVE",
        actor="alice-lead",
        repo_dir=str(tmp_path),
    )

    assert res.success is True
    assert res.status == "RELEASED"
    assert res.tag == "v1.0.1"
    assert os.path.exists(os.path.join(tmp_path, ".git", "refs", "tags", "v1.0.1"))
    assert (tmp_path / "releases" / "RELEASE_v1.0.1.md").read_text(encoding="utf-8") == report.release_plan.release_notes_md
    assert any(ev.action == "HUMAN_APPROVAL_RECORDED" for ev in res.audit_trail)
    assert any(ev.action == "RELEASE_PUBLISHED" for ev in res.audit_trail)

    rolled_back = executor.rollback("v1.0.1", str(tmp_path), actor="alice-lead")

    assert rolled_back.success is True
    assert rolled_back.status == "ROLLED_BACK"
    assert not (tmp_path / "releases" / "RELEASE_v1.0.1.md").exists()
    assert subprocess.run(["git", "rev-parse", "-q", "--verify", "refs/tags/v1.0.1"], cwd=tmp_path).returncode != 0


def test_executor_reject():
    executor = ReleaseExecutor()
    report = create_dummy_report()

    res = executor.execute(
        report=report,
        decision="REJECT",
        actor="bob-security",
        reason="Security audit required"
    )

    assert res.success is False
    assert res.status == "REJECTED"
    assert any(ev.action == "APPROVAL_REJECTED" for ev in res.audit_trail)


def test_executor_head_drift_abort():
    executor = ReleaseExecutor()
    report = create_dummy_report()

    # Current HEAD has drifted to another commit after analysis
    res = executor.execute(
        report=report,
        decision="APPROVE",
        actor="alice-lead",
        current_head_sha="sha_tampered_999"
    )

    assert res.success is False
    assert res.status == "ABORTED_DRIFT"
    assert "Repository changed after analysis" in res.message
    assert any(ev.action == "HEAD_DRIFT_DETECTED" for ev in res.audit_trail)


def test_executor_blocked_release():
    executor = ReleaseExecutor()
    report = create_dummy_report(blockers=["Exposed secret detected in git diff"])

    res = executor.execute(
        report=report,
        decision="APPROVE",
        actor="alice-lead"
    )

    assert res.success is False
    assert res.status == "BLOCKED"
    assert any(ev.action == "EXECUTION_BLOCKED" for ev in res.audit_trail)


def test_executor_rejects_invalid_decision():
    res = ReleaseExecutor().execute(create_dummy_report(), decision="MAYBE")

    assert not res.success
    assert res.status == "INVALID_DECISION"


def test_executor_does_not_claim_success_when_real_tag_creation_fails(tmp_path):
    create_git_repo(tmp_path)
    subprocess.run(["git", "tag", "-a", "v1.0.1", "-m", "existing tag"], cwd=tmp_path, check=True)
    report = create_dummy_report().model_copy(update={"analyzed_head_sha": subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()})

    res = ReleaseExecutor().execute(report, decision="APPROVE", repo_dir=str(tmp_path))

    assert not res.success
    assert res.status == "FAILED"
    assert "Git tag creation failed" in res.message
    assert not (tmp_path / "releases" / "RELEASE_v1.0.1.md").exists()


def test_executor_detects_real_repository_head_drift(tmp_path):
    analyzed_sha = create_git_repo(tmp_path)
    report = create_dummy_report().model_copy(update={"analyzed_head_sha": analyzed_sha})
    (tmp_path / "README.md").write_text("changed after analysis\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "chore: drift after analysis"], cwd=tmp_path, check=True, capture_output=True)

    res = ReleaseExecutor().execute(report, decision="APPROVE", repo_dir=str(tmp_path))

    assert not res.success
    assert res.status == "ABORTED_DRIFT"
    assert any(event.action == "HEAD_DRIFT_DETECTED" for event in res.audit_trail)
    assert not (tmp_path / "releases" / "RELEASE_v1.0.1.md").exists()
