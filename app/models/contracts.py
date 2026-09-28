"""Data contracts and schemas for Release Captain agents and pipeline."""
from __future__ import annotations
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class VersionBump(str, Enum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    NONE = "none"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Recommendation(str, Enum):
    APPROVED_TO_RELEASE = "approved_to_release"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"


class CommitInfo(BaseModel):
    sha: str
    message: str
    author: Optional[str] = None
    date: Optional[str] = None


class FileDiff(BaseModel):
    filename: str
    status: str = "modified"  # added, modified, removed
    previous_filename: Optional[str] = None
    additions: int = 0
    deletions: int = 0
    patch: Optional[str] = None


class RepoSnapshot(BaseModel):
    repository: str
    base_ref: str
    head_ref: str
    base_sha: Optional[str] = None
    head_sha: Optional[str] = None
    commits: List[CommitInfo] = Field(default_factory=list)
    diffs: List[FileDiff] = Field(default_factory=list)
    changed_files: List[str] = Field(default_factory=list)


# --- Code Agent Contracts ---

class ChangeItem(BaseModel):
    type: str  # feat, fix, chore, refactor, docs, perf, etc.
    description: str
    breaking: bool = False
    files: List[str] = Field(default_factory=list)


class BreakingChange(BaseModel):
    component: str
    identifier: str
    old_signature: Optional[str] = None
    new_signature: Optional[str] = None
    impact: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


class CodeAnalysisResult(BaseModel):
    changes: List[ChangeItem] = Field(default_factory=list)
    breaking_changes: List[BreakingChange] = Field(default_factory=list)
    suggested_bump: VersionBump = VersionBump.PATCH
    reason: str
    total_additions: int = 0
    total_deletions: int = 0
    files_changed_count: int = 0


# --- Test Agent Contracts ---

class TestCaseResult(BaseModel):
    __test__ = False
    name: str
    status: str  # passed, failed, skipped
    error_message: Optional[str] = None


class TestRunResult(BaseModel):
    __test__ = False
    framework: str = "pytest"
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    failure_details: List[TestCaseResult] = Field(default_factory=list)
    execution_error: Optional[str] = None
    diagnostics: Optional[str] = None


# --- Security Agent Contracts ---

class SecurityFinding(BaseModel):
    tool: str  # gitleaks, semgrep, osv-scanner, trivy
    severity: RiskLevel
    title: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None


class SecurityScanResult(BaseModel):
    findings: List[SecurityFinding] = Field(default_factory=list)
    secrets_count: int = 0
    sast_high_count: int = 0
    sast_medium_count: int = 0
    dependency_critical_count: int = 0
    dependency_high_count: int = 0


# --- Risk Engine Contracts ---

class RiskFactor(BaseModel):
    name: str
    weight: int
    description: str


class RiskEvaluation(BaseModel):
    score: int = 0
    level: RiskLevel = RiskLevel.LOW
    factors: List[RiskFactor] = Field(default_factory=list)


# --- Release Planner Agent Contracts ---

class ReleasePlanResult(BaseModel):
    current_version: str
    proposed_version: str
    bump_type: VersionBump
    risk_level: RiskLevel
    risk_score: int
    release_notes_md: str
    recommendation: Recommendation
    blockers: List[str] = Field(default_factory=list)


# --- Orchestrator Consolidated Output ---

class ReleaseExecutionReport(BaseModel):
    repository: str
    base_ref: str
    head_ref: str
    code_analysis: CodeAnalysisResult
    test_results: TestRunResult
    security_results: SecurityScanResult
    risk_evaluation: RiskEvaluation
    release_plan: ReleasePlanResult
    analyzed_head_sha: Optional[str] = None
    timestamp: Optional[str] = None
