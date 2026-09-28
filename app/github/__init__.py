"""GitHub & Git Integration Suite for Release Captain."""
import os
from typing import Optional, Tuple
from app.models.contracts import RepoSnapshot
from app.github.git_service import LocalGitService, GitCommandError
from app.github.github_client import GitHubClient, GitHubAPIError

__all__ = [
    "LocalGitService",
    "GitCommandError",
    "GitHubClient",
    "GitHubAPIError",
    "resolve_repository_snapshot",
]


def resolve_repository_snapshot(
    target: str = ".",
    base_ref: Optional[str] = None,
    head_ref: str = "HEAD",
) -> Tuple[RepoSnapshot, Optional[str]]:
    """
    Resolves repository snapshot from either a local directory path or a remote GitHub identifier.
    Returns: (RepoSnapshot, local_repo_dir or None)
    """
    # 1. Check if target is a local directory or relative path
    expanded_path = os.path.abspath(target)
    if os.path.exists(expanded_path) or os.path.exists(os.path.join(expanded_path, ".git")):
        git_service = LocalGitService(repo_dir=expanded_path)
        if git_service.is_git_repo():
            snapshot = git_service.extract_snapshot(base_ref=base_ref, head_ref=head_ref)
            return snapshot, expanded_path

    # 2. Check if target looks like a GitHub URL or owner/repo
    is_owner_repo = "/" in target and not os.path.isabs(target) and len(target.split("/")) == 2
    if "github.com" in target or is_owner_repo:
        client = GitHubClient()
        repo_id = client.parse_repo_identifier(target)
        actual_base = base_ref or client.get_latest_tag(repo_id) or "v0.1.0"
        actual_head = "main" if head_ref == "HEAD" else head_ref
        snapshot = client.compare_commits(
            owner_repo=repo_id,
            base_ref=actual_base,
            head_ref=actual_head,
        )
        return snapshot, None

    # 3. Fallback: try LocalGitService anyway on the path
    git_service = LocalGitService(repo_dir=expanded_path)
    snapshot = git_service.extract_snapshot(base_ref=base_ref, head_ref=head_ref)
    return snapshot, expanded_path
