"""Deterministic Risk Engine: Explainable factor-weighted scoring matrix."""
from __future__ import annotations
from typing import List

from app.config import settings
from app.models.contracts import (
    CodeAnalysisResult,
    TestRunResult,
    SecurityScanResult,
    RiskEvaluation,
    RiskFactor,
    RiskLevel,
    RepoSnapshot,
)

AUTH_KEYWORDS = {"auth", "oauth", "login", "jwt", "session", "permission", "security", "token", "password"}
DB_MIGRATION_KEYWORDS = {"migration", "alembic", "schema.sql", "flyway", "liquibase", "migrate"}


class RiskEngine:
    """Calculates deterministic, fully explainable risk scores from multi-agent outputs."""

    def evaluate(
        self,
        snapshot: RepoSnapshot,
        code_result: CodeAnalysisResult,
        test_result: TestRunResult,
        security_result: SecurityScanResult,
    ) -> RiskEvaluation:
        factors: List[RiskFactor] = []
        score = 0

        # 1. Database Migration Detection
        db_files = [
            f for f in snapshot.changed_files
            if any(k in f.lower() for k in DB_MIGRATION_KEYWORDS) or f.endswith(".sql")
        ]
        if db_files:
            w = settings.WEIGHT_DB_MIGRATION
            score += w
            factors.append(RiskFactor(
                name="Database Schema / Migration Modified",
                weight=w,
                description=f"Changes detected in migration files: {', '.join(db_files[:3])}"
            ))

        # 2. Authentication & Authorization Detection
        auth_files = [
            f for f in snapshot.changed_files
            if not any(part in {"__pycache__", "vendor", "generated"} for part in f.replace("\\", "/").lower().split("/"))
            and not f.lower().endswith((".pyc", ".pyo"))
            and any(k in f.lower() for k in AUTH_KEYWORDS)
        ]
        if auth_files:
            w = settings.WEIGHT_AUTH_CHANGE
            score += w
            factors.append(RiskFactor(
                name="Authentication / Security Middleware Modified",
                weight=w,
                description=f"Security-sensitive files changed: {', '.join(auth_files[:3])}"
            ))

        # 3. Public API / Breaking Changes
        if code_result.breaking_changes:
            w = settings.WEIGHT_PUBLIC_API_CHANGE * min(3, len(code_result.breaking_changes))
            score += w
            factors.append(RiskFactor(
                name="Breaking Public API Changes Detected",
                weight=w,
                description=f"{len(code_result.breaking_changes)} breaking change(s) in API/function contracts"
            ))

        # 4. Large Diff
        total_diff_lines = code_result.total_additions + code_result.total_deletions
        if total_diff_lines > 1000:
            w = settings.WEIGHT_LARGE_DIFF
            score += w
            factors.append(RiskFactor(
                name="Large Codebase Delta",
                weight=w,
                description=f"Large diff with {total_diff_lines:,} modified lines across {code_result.files_changed_count} files"
            ))

        # 5. Dependency Updates
        dep_files = [f for f in snapshot.changed_files if any(p in f for p in ("requirements", "package.json", "go.mod", "Cargo.toml"))]
        if dep_files:
            w = settings.WEIGHT_DEPENDENCY_UPDATE
            score += w
            factors.append(RiskFactor(
                name="Dependency Manifest Modified",
                weight=w,
                description=f"Package manifests updated: {', '.join(dep_files)}"
            ))

        # 6. Test Failures
        if test_result.failed > 0:
            w = settings.WEIGHT_TEST_FAILURE * min(3, test_result.failed)
            score += w
            factors.append(RiskFactor(
                name="Automated Test Suite Failures",
                weight=w,
                description=f"{test_result.failed} automated test(s) failed in sandbox execution"
            ))
        if test_result.execution_error:
            w = settings.WEIGHT_TEST_FAILURE
            score += w
            factors.append(RiskFactor(
                name="Test Execution Could Not Be Verified",
                weight=w,
                description="The test runner failed before producing a reliable test result",
            ))

        # 7. Secrets Detected
        if security_result.secrets_count > 0:
            w = settings.WEIGHT_SECRET_FOUND * security_result.secrets_count
            score += w
            factors.append(RiskFactor(
                name="Hardcoded Secrets / Credentials Exposed",
                weight=w,
                description=f"{security_result.secrets_count} unencrypted secret(s) found in commit delta"
            ))

        # 8. Critical / High Security Findings
        crit_cves = security_result.dependency_critical_count
        high_sast = security_result.sast_high_count
        if crit_cves > 0:
            w = settings.WEIGHT_CRITICAL_CVE * crit_cves
            score += w
            factors.append(RiskFactor(
                name="Critical CVE Vulnerabilities",
                weight=w,
                description=f"{crit_cves} critical dependency vulnerability(ies) detected"
            ))
        if high_sast > 0:
            w = settings.WEIGHT_HIGH_CVE * high_sast
            score += w
            factors.append(RiskFactor(
                name="High-Severity SAST Security Anti-Patterns",
                weight=w,
                description=f"{high_sast} high-severity code security finding(s)"
            ))

        # Map to Categorical Level
        if score >= 15:
            level = RiskLevel.CRITICAL
        elif score >= 10:
            level = RiskLevel.HIGH
        elif score >= 5:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return RiskEvaluation(
            score=score,
            level=level,
            factors=factors,
        )
