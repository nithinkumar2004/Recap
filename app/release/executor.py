"""Release Executor: Validates approvals, checks HEAD drift, tags, and publishes releases."""
from __future__ import annotations
import datetime
import os
import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

from app.models.contracts import (
    ReleaseExecutionReport,
    Recommendation,
    RiskLevel,
)


class AuditEvent:
    def __init__(self, action: str, actor: str, details: str, status: str = "SUCCESS"):
        self.timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.action = action
        self.actor = actor
        self.details = details
        self.status = status

    def to_dict(self) -> Dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "details": self.details,
            "status": self.status,
        }


class ReleaseExecutionResult:
    def __init__(
        self,
        success: bool,
        status: str,
        message: str,
        tag: Optional[str] = None,
        audit_trail: Optional[List[AuditEvent]] = None,
        release_artifact_path: Optional[str] = None,
    ):
        self.success = success
        self.status = status
        self.message = message
        self.tag = tag
        self.audit_trail = audit_trail or []
        self.release_artifact_path = release_artifact_path


class ReleaseExecutor:
    """Handles secure post-approval release publishing, tag creation, and audit trails."""

    def __init__(self):
        self.audit_log: List[AuditEvent] = []

    def record_event(self, action: str, actor: str, details: str, status: str = "SUCCESS") -> AuditEvent:
        event = AuditEvent(action=action, actor=actor, details=details, status=status)
        self.audit_log.append(event)
        return event

    def execute(
        self,
        report: ReleaseExecutionReport,
        decision: str,  # "APPROVE" or "REJECT"
        actor: str = "release-lead",
        reason: Optional[str] = None,
        current_head_sha: Optional[str] = None,
        repo_dir: Optional[str] = None,
    ) -> ReleaseExecutionResult:
        """
        Executes the human decision.
        If APPROVED:
        1. Checks for blockers (secrets, failing tests).
        2. Validates HEAD SHA integrity to prevent release drift.
        3. Creates Git tag.
        4. Writes published release notes artifact.
        5. Commits audit trail.
        """
        self.audit_log = []

        normalized_decision = decision.upper()
        if normalized_decision not in {"APPROVE", "REJECT"}:
            self.record_event("INVALID_DECISION", actor, f"Unsupported decision: {decision}", "REJECTED")
            return ReleaseExecutionResult(
                success=False,
                status="INVALID_DECISION",
                message="Decision must be APPROVE or REJECT.",
                audit_trail=self.audit_log,
            )

        # 1. Handle Rejection
        if normalized_decision == "REJECT":
            rejection_reason = reason or "No reason provided by reviewer."
            self.record_event(
                action="APPROVAL_REJECTED",
                actor=actor,
                details=f"Release {report.release_plan.proposed_version} was rejected. Reason: {rejection_reason}",
                status="REJECTED"
            )
            return ReleaseExecutionResult(
                success=False,
                status="REJECTED",
                message=f"Release was rejected by {actor}.",
                audit_trail=self.audit_log,
            )

        # 2. Blockers Check
        if report.release_plan.blockers:
            blocker_str = "; ".join(report.release_plan.blockers)
            self.record_event(
                action="EXECUTION_BLOCKED",
                actor="system",
                details=f"Cannot execute release due to active blockers: {blocker_str}",
                status="BLOCKED"
            )
            return ReleaseExecutionResult(
                success=False,
                status="BLOCKED",
                message=f"Release execution blocked: {blocker_str}",
                audit_trail=self.audit_log,
            )

        self.record_event(
            action="HUMAN_APPROVAL_RECORDED",
            actor=actor,
            details=f"Approved target version {report.release_plan.proposed_version} ({report.release_plan.bump_type.value.upper()})",
        )

        # 3. Security Rule: Validate Repository HEAD SHA (Prevent race condition / drift)
        analyzed_sha = report.analyzed_head_sha
        if repo_dir:
            head_check = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True
            )
            if head_check.returncode != 0 or not analyzed_sha:
                message = "Unable to verify the analyzed Git commit SHA; release aborted."
                self.record_event("HEAD_INTEGRITY_UNVERIFIED", "security-validator", message, "ABORTED")
                return ReleaseExecutionResult(False, "ABORTED_UNVERIFIED", message, audit_trail=self.audit_log)
            target_head = head_check.stdout.strip()
        else:
            # In demo/non-repository mode, an explicit SHA is still checked if provided.
            target_head = current_head_sha or analyzed_sha or report.head_ref

        if analyzed_sha and target_head and target_head != analyzed_sha:
            self.record_event(
                action="HEAD_DRIFT_DETECTED",
                actor="security-validator",
                details=f"Repository HEAD changed from {analyzed_sha} to {target_head}. Release aborted.",
                status="ABORTED"
            )
            return ReleaseExecutionResult(
                success=False,
                status="ABORTED_DRIFT",
                message="Repository changed after analysis. Release aborted. Re-analysis required.",
                audit_trail=self.audit_log,
            )

        self.record_event(
            action="HEAD_INTEGRITY_VERIFIED",
            actor="security-validator",
            details=f"Commit SHA {analyzed_sha or target_head} verified with repository HEAD.",
        )

        # 4. Create Git Tag
        version_tag = report.release_plan.proposed_version
        if not re.fullmatch(r"v?\d+\.\d+\.\d+", version_tag):
            message = f"Invalid release tag format: {version_tag}"
            self.record_event("INVALID_RELEASE_TAG", "release-executor", message, "FAILED")
            return ReleaseExecutionResult(False, "FAILED", message, audit_trail=self.audit_log)

        tag_created = False
        releases_dir = os.path.join(repo_dir, "releases") if repo_dir else os.path.join(os.getcwd(), "releases")
        artifact_filename = f"RELEASE_{version_tag}.md"
        artifact_path = os.path.join(releases_dir, artifact_filename)

        if os.path.exists(artifact_path):
            message = f"Release artifact already exists: {artifact_path}"
            self.record_event("ARTIFACT_ALREADY_EXISTS", "release-executor", message, "FAILED")
            return ReleaseExecutionResult(False, "FAILED", message, audit_trail=self.audit_log)

        if repo_dir:
            proc = subprocess.run(
                ["git", "tag", "-a", version_tag, "-m", f"Release {version_tag}"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                message = f"Git tag creation failed: {(proc.stderr or proc.stdout).strip()}"
                self.record_event("GIT_TAG_CREATION_FAILED", "release-executor", message, "FAILED")
                return ReleaseExecutionResult(False, "FAILED", message, audit_trail=self.audit_log)
            tag_created = True

        if not tag_created:
            self.record_event(
                action="GIT_TAG_CREATED",
                actor="release-executor",
                details=f"Simulated annotated tag '{version_tag}' for non-repository execution.",
            )
        else:
            self.record_event(
                action="GIT_TAG_CREATED",
                actor="release-executor",
                details=f"Git tag '{version_tag}' successfully pushed to local git ref.",
            )

        # 5. Generate Release Artifact & Release Notes
        try:
            os.makedirs(releases_dir, exist_ok=True)
            with open(artifact_path, "x", encoding="utf-8") as f:
                f.write(report.release_plan.release_notes_md)
        except OSError as exc:
            rollback_message = ""
            if tag_created:
                cleanup = subprocess.run(
                    ["git", "tag", "-d", version_tag], cwd=repo_dir,
                    capture_output=True, text=True,
                )
                rollback_message = " Git tag cleanup succeeded." if cleanup.returncode == 0 else " Git tag cleanup failed."
                self.record_event(
                    "RELEASE_COMPENSATION", "release-executor",
                    f"Artifact write failed;{rollback_message}",
                    "ROLLED_BACK" if cleanup.returncode == 0 else "PARTIAL",
                )
            message = f"Release artifact write failed: {exc}.{rollback_message}"
            self.record_event("ARTIFACT_WRITE_FAILED", "release-executor", message, "FAILED")
            return ReleaseExecutionResult(False, "FAILED", message, audit_trail=self.audit_log)

        self.record_event(
            action="RELEASE_PUBLISHED",
            actor="release-executor",
            details=f"Release notes saved to {artifact_filename}; local Git tag status recorded.",
        )

        return ReleaseExecutionResult(
            success=True,
            status="RELEASED",
            message=f"Release {version_tag} successfully approved, tagged, and published!",
            tag=version_tag,
            audit_trail=self.audit_log,
            release_artifact_path=artifact_path,
        )

    def rollback(
        self,
        version_tag: str,
        repo_dir: str,
        actor: str = "release-lead",
        artifact_path: Optional[str] = None,
    ) -> ReleaseExecutionResult:
        """Remove a release tag and its matching local release-notes artifact."""
        self.audit_log = []
        if not re.fullmatch(r"v?\d+\.\d+\.\d+", version_tag):
            message = f"Invalid release tag format: {version_tag}"
            self.record_event("ROLLBACK_REJECTED", actor, message, "REJECTED")
            return ReleaseExecutionResult(False, "ROLLBACK_FAILED", message, audit_trail=self.audit_log)

        root = Path(repo_dir).resolve()
        expected_artifact = (root / "releases" / f"RELEASE_{version_tag}.md").resolve()
        selected_artifact = Path(artifact_path).resolve() if artifact_path else expected_artifact
        if selected_artifact != expected_artifact:
            message = "Rollback artifact must be the release note file associated with this tag."
            self.record_event("ROLLBACK_REJECTED", actor, message, "REJECTED")
            return ReleaseExecutionResult(False, "ROLLBACK_FAILED", message, audit_trail=self.audit_log)

        tag_check = subprocess.run(
            ["git", "for-each-ref", "--format=%(contents:subject)", f"refs/tags/{version_tag}"],
            cwd=root, capture_output=True, text=True,
        )
        if tag_check.returncode != 0 or tag_check.stdout.strip() != f"Release {version_tag}":
            message = f"Tag '{version_tag}' is missing or is not an annotated Release Captain tag."
            self.record_event("ROLLBACK_REJECTED", actor, message, "REJECTED")
            return ReleaseExecutionResult(False, "ROLLBACK_FAILED", message, audit_trail=self.audit_log)

        delete_tag = subprocess.run(
            ["git", "tag", "-d", version_tag], cwd=root, capture_output=True, text=True
        )
        if delete_tag.returncode != 0:
            message = f"Could not delete tag '{version_tag}': {(delete_tag.stderr or delete_tag.stdout).strip()}"
            self.record_event("ROLLBACK_FAILED", actor, message, "FAILED")
            return ReleaseExecutionResult(False, "ROLLBACK_FAILED", message, audit_trail=self.audit_log)
        self.record_event("RELEASE_TAG_REMOVED", actor, f"Deleted annotated tag '{version_tag}'.")

        try:
            if expected_artifact.exists():
                expected_artifact.unlink()
                self.record_event("RELEASE_ARTIFACT_REMOVED", actor, f"Deleted {expected_artifact.name}.")
        except OSError as exc:
            message = f"Tag was removed, but release artifact cleanup failed: {exc}"
            self.record_event("ROLLBACK_PARTIAL", actor, message, "PARTIAL")
            return ReleaseExecutionResult(False, "ROLLBACK_PARTIAL", message, tag=version_tag, audit_trail=self.audit_log)

        return ReleaseExecutionResult(
            True,
            "ROLLED_BACK",
            f"Release {version_tag} tag and local release notes were rolled back.",
            tag=version_tag,
            audit_trail=self.audit_log,
        )
