"""FastAPI Release Captain Endpoints."""
from __future__ import annotations
import uuid
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.models.contracts import (
    RepoSnapshot,
    CommitInfo,
    FileDiff,
    TestRunResult,
    ReleaseExecutionReport,
    Recommendation,
)
from app.core.orchestrator import ReleaseOrchestrator

router = APIRouter(prefix="/api/v1/releases", tags=["releases"])

# In-memory storage for runs (can be backed by Postgres)
RELEASES_DB: Dict[str, Dict[str, Any]] = {}
orchestrator = ReleaseOrchestrator()


class AnalyzeRequest(BaseModel):
    repository: str
    base_ref: Optional[str] = None
    head_ref: str = "main"
    snapshot: Optional[RepoSnapshot] = None
    repo_path: Optional[str] = None


class ApprovalRequest(BaseModel):
    actor: str
    decision: str  # APPROVE or REJECT
    reason: Optional[str] = None


@router.post("/analyze")
def trigger_analysis(request: AnalyzeRequest):
    """Triggers the full multi-agent pipeline for release evaluation."""
    release_id = f"rel_{uuid.uuid4().hex[:8]}"

    repo_dir = None
    if request.snapshot:
        snapshot = request.snapshot
    else:
        target = request.repo_path or request.repository
        try:
            from app.github import resolve_repository_snapshot
            snapshot, repo_dir = resolve_repository_snapshot(
                target=target,
                base_ref=request.base_ref,
                head_ref=request.head_ref,
            )
        except Exception:
            snapshot = RepoSnapshot(
                repository=request.repository,
                base_ref=request.base_ref or "v1.0.0",
                head_ref=request.head_ref,
                commits=[CommitInfo(sha="c123456", message="chore: initialize release pipeline")],
                changed_files=[],
                diffs=[]
            )

    report = orchestrator.execute_pipeline(
        snapshot=snapshot,
        current_version=snapshot.base_ref or request.base_ref or "v1.0.0",
        repo_dir=repo_dir,
    )

    RELEASES_DB[release_id] = {
        "release_id": release_id,
        "repository": request.repository,
        "status": "AWAITING_APPROVAL" if report.release_plan.recommendation != Recommendation.BLOCKED else "BLOCKED",
        "report": report.model_dump(),
        "approval": None,
    }

    return {
        "release_id": release_id,
        "status": RELEASES_DB[release_id]["status"],
        "proposed_version": report.release_plan.proposed_version,
        "risk_level": report.risk_evaluation.level,
        "risk_score": report.risk_evaluation.score,
    }


@router.get("/{release_id}")
def get_release_status(release_id: str):
    """Retrieves full release analysis, risk factors, and release notes."""
    if release_id not in RELEASES_DB:
        raise HTTPException(status_code=404, detail="Release not found")
    return RELEASES_DB[release_id]


@router.post("/{release_id}/approve")
def approve_release(release_id: str, request: ApprovalRequest):
    """Submits human approval decision."""
    if release_id not in RELEASES_DB:
        raise HTTPException(status_code=404, detail="Release not found")
    
    release = RELEASES_DB[release_id]
    if release["status"] == "BLOCKED":
        raise HTTPException(status_code=400, detail="Cannot approve a blocked release.")

    release["status"] = "APPROVED" if request.decision.upper() == "APPROVE" else "REJECTED"
    release["approval"] = {
        "actor": request.actor,
        "decision": request.decision.upper(),
        "reason": request.reason
    }
    return {
        "release_id": release_id,
        "status": release["status"],
        "message": f"Release successfully {release['status'].lower()} by {request.actor}"
    }
