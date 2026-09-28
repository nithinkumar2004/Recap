"""Release Planner Agent: Synthesizes multi-agent intelligence into release plan & notes."""
from __future__ import annotations
import re
from typing import Optional, List
import httpx

from app.config import settings
from app.models.contracts import (
    CodeAnalysisResult,
    TestRunResult,
    SecurityScanResult,
    RiskEvaluation,
    ReleasePlanResult,
    VersionBump,
    RiskLevel,
    Recommendation,
)


def bump_semver(current_version: str, bump: VersionBump) -> str:
    """Calculates next SemVer tag maintaining optional 'v' prefix."""
    has_v = current_version.startswith("v")
    clean_ver = current_version[1:] if has_v else current_version
    parts = clean_ver.split(".")
    
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        major, minor, patch = 1, 0, 0

    if bump == VersionBump.MAJOR:
        major += 1
        minor = 0
        patch = 0
    elif bump == VersionBump.MINOR:
        minor += 1
        patch = 0
    elif bump == VersionBump.PATCH:
        patch += 1
    # If bump == NONE, keep the same version

    prefix = "v" if has_v else ""
    return f"{prefix}{major}.{minor}.{patch}"


class ReleasePlannerAgent:
    """Agent that plans the release, categorizes changes, and writes release notes."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OPENROUTER_API_KEY
        self.model = settings.OPENROUTER_MODEL

    def plan(
        self,
        current_version: str,
        code_result: CodeAnalysisResult,
        test_result: TestRunResult,
        security_result: SecurityScanResult,
        risk_result: RiskEvaluation,
    ) -> ReleasePlanResult:
        # 1. Determine Proposed Version
        proposed_version = bump_semver(current_version, code_result.suggested_bump)

        # 2. Check for Hard Blockers
        blockers: List[str] = []
        if security_result.secrets_count > 0:
            blockers.append(f"{security_result.secrets_count} unencrypted secret(s) detected in commit diff.")
        if security_result.dependency_critical_count > 0:
            blockers.append(f"{security_result.dependency_critical_count} critical CVE(s) present in dependencies.")
        if test_result.failed > 0:
            blockers.append(f"{test_result.failed} automated test suite failure(s) observed.")
        if test_result.execution_error:
            blockers.append(f"Test execution could not be verified: {test_result.execution_error}")

        # 3. Determine Recommendation
        if blockers:
            recommendation = Recommendation.BLOCKED
        elif risk_result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL) or code_result.breaking_changes:
            recommendation = Recommendation.APPROVAL_REQUIRED
        else:
            # Low or Medium risk with zero test/security failures still requires human approval in Release Captain
            recommendation = Recommendation.APPROVAL_REQUIRED

        # 4. Generate Release Notes
        notes_md = None
        if self.api_key:
            try:
                notes_md = self._llm_generate_notes(
                    proposed_version=proposed_version,
                    code_result=code_result,
                    test_result=test_result,
                    security_result=security_result,
                    risk_result=risk_result,
                )
            except Exception:
                pass

        if not notes_md:
            notes_md = self._deterministic_generate_notes(
                proposed_version=proposed_version,
                current_version=current_version,
                code_result=code_result,
                test_result=test_result,
                security_result=security_result,
                risk_result=risk_result,
                blockers=blockers,
            )

        return ReleasePlanResult(
            current_version=current_version,
            proposed_version=proposed_version,
            bump_type=code_result.suggested_bump,
            risk_level=risk_result.level,
            risk_score=risk_result.score,
            release_notes_md=notes_md,
            recommendation=recommendation,
            blockers=blockers,
        )

    def _deterministic_generate_notes(
        self,
        proposed_version: str,
        current_version: str,
        code_result: CodeAnalysisResult,
        test_result: TestRunResult,
        security_result: SecurityScanResult,
        risk_result: RiskEvaluation,
        blockers: List[str],
    ) -> str:
        lines: List[str] = [
            f"# Release {proposed_version}",
            f"**Baseline Version:** `{current_version}` -> **Target Version:** `{proposed_version}`  ",
            f"**Risk Rating:** `{risk_result.level.value}` (Score: {risk_result.score})  ",
            "",
        ]

        if blockers:
            lines.append("### [!] RELEASE BLOCKED")
            for b in blockers:
                lines.append(f"- [BLOCKER] {b}")
            lines.append("")

        # Features
        features = [c for c in code_result.changes if c.type == "feat"]
        if features:
            lines.append("### New Features")
            for f in features:
                lines.append(f"- {f.description}")
            lines.append("")

        # Bug Fixes
        fixes = [c for c in code_result.changes if c.type == "fix"]
        if fixes:
            lines.append("### Bug Fixes")
            for f in fixes:
                lines.append(f"- {f.description}")
            lines.append("")

        # Breaking Changes
        if code_result.breaking_changes:
            lines.append("### Breaking Changes")
            for b in code_result.breaking_changes:
                lines.append(f"- **{b.component}** (`{b.identifier}`): {b.impact}")
                if b.old_signature and b.new_signature:
                    lines.append(f"  - Old: `{b.old_signature}`")
                    lines.append(f"  - New: `{b.new_signature}`")
            lines.append("")

        # Other changes
        others = [c for c in code_result.changes if c.type not in ("feat", "fix")]
        if others:
            lines.append("### Maintenance & Chores")
            for o in others:
                lines.append(f"- [{o.type}] {o.description}")
            lines.append("")

        # Quality & Security Verification
        lines.append("### Quality & Verification Health")
        if test_result.framework != "skipped" and test_result.total == 0 and not test_result.execution_error:
            lines.append("- **Automated Tests:** No tests discovered (0 tests run)")
        else:
            lines.append(f"- **Automated Tests:** {test_result.passed}/{test_result.total} passed ({test_result.failed} failed, {test_result.skipped} skipped) in {test_result.duration_seconds}s")
        if test_result.execution_error:
            lines.append(f"- **Test Execution Error:** {test_result.execution_error.splitlines()[-1]}")
        lines.append(f"- **Secrets Detected:** {security_result.secrets_count}")
        lines.append(f"- **SAST High/Critical:** {security_result.sast_high_count}")
        lines.append(f"- **Dependency CVEs (High/Critical):** {security_result.dependency_critical_count + security_result.dependency_high_count}")
        lines.append("")

        # Risk Factors
        if risk_result.factors:
            lines.append("### Explainable Risk Factors")
            for rf in risk_result.factors:
                lines.append(f"- **+{rf.weight}**: {rf.name} ({rf.description})")
            lines.append("")

        return "\n".join(lines)

    def _llm_generate_notes(
        self,
        proposed_version: str,
        code_result: CodeAnalysisResult,
        test_result: TestRunResult,
        security_result: SecurityScanResult,
        risk_result: RiskEvaluation,
    ) -> Optional[str]:
        prompt = (
            f"You are the Release Captain Planner. Generate clean, professional GitHub Release notes in Markdown for release {proposed_version}.\n"
            f"Changes:\n"
            f"- Features: {[c.description for c in code_result.changes if c.type == 'feat']}\n"
            f"- Fixes: {[c.description for c in code_result.changes if c.type == 'fix']}\n"
            f"- Breaking Changes: {[b.impact for b in code_result.breaking_changes]}\n"
            f"Test stats: {test_result.passed}/{test_result.total} passed.\n"
            f"Security: {security_result.secrets_count} secrets, {security_result.sast_high_count} SAST high, {security_result.dependency_critical_count} critical CVEs.\n"
            f"Risk: {risk_result.level.value} (Score {risk_result.score}).\n"
            "Format with standard release note headings."
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{settings.OPENROUTER_BASE_URL}/chat/completions", headers=headers, json=payload)
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
        return None
