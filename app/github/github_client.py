"""Remote GitHub Client: Fetches repository snapshot and diffs via GitHub REST API."""
from __future__ import annotations
import re
from typing import Optional, List, Dict, Any
import httpx

from app.config import settings
from app.models.contracts import RepoSnapshot, CommitInfo, FileDiff


class GitHubAPIError(Exception):
    """Raised when GitHub API request fails."""
    pass


class GitHubClient:
    """Client for querying GitHub API to inspect repositories, commits, and diffs."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.GITHUB_TOKEN
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Release-Captain-Agent",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    @staticmethod
    def parse_repo_identifier(repo_identifier: str) -> str:
        """
        Parses 'owner/repo' or 'https://github.com/owner/repo.git' to 'owner/repo'.
        """
        clean = repo_identifier.strip().rstrip("/")
        if clean.endswith(".git"):
            clean = clean[:-4]
        match = re.search(r"github\.com[:/]([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+)$", clean)
        if match:
            return match.group(1)
        if "/" in clean and not clean.startswith("http"):
            parts = clean.split("/")
            if len(parts) == 2:
                return f"{parts[0]}/{parts[1]}"
        return repo_identifier

    def get_latest_tag(self, owner_repo: str) -> Optional[str]:
        """Fetches the latest release tag or tag name for the repo."""
        repo = self.parse_repo_identifier(owner_repo)
        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.get(f"{self.base_url}/repos/{repo}/releases/latest", headers=self.headers)
                if res.status_code == 200:
                    return res.json().get("tag_name")
                
                # Fallback to tags list
                tags_res = client.get(f"{self.base_url}/repos/{repo}/tags", headers=self.headers)
                if tags_res.status_code == 200:
                    tags = tags_res.json()
                    if tags and isinstance(tags, list):
                        return tags[0].get("name")
        except Exception:
            pass
        return None

    def compare_commits(
        self,
        owner_repo: str,
        base_ref: str,
        head_ref: str = "main",
    ) -> RepoSnapshot:
        """
        Compares base and head using GitHub compare API:
        GET /repos/{owner}/{repo}/compare/{base}...{head}
        """
        repo = self.parse_repo_identifier(owner_repo)
        url = f"{self.base_url}/repos/{repo}/compare/{base_ref}...{head_ref}"

        with httpx.Client(timeout=30.0) as client:
            res = client.get(url, headers=self.headers)
            if res.status_code != 200:
                raise GitHubAPIError(
                    f"GitHub compare failed ({res.status_code}): {res.text}"
                )
            data = res.json()

        commits: List[CommitInfo] = []
        for c in data.get("commits", []):
            commit_data = c.get("commit", {})
            author_info = commit_data.get("author", {})
            commits.append(CommitInfo(
                sha=c.get("sha", ""),
                message=commit_data.get("message", ""),
                author=author_info.get("name", "Unknown"),
                date=author_info.get("date"),
            ))

        diffs: List[FileDiff] = []
        changed_files: List[str] = []
        for f in data.get("files", []):
            fname = f.get("filename", "")
            changed_files.append(fname)
            diffs.append(FileDiff(
                filename=fname,
                status=f.get("status", "modified"),
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch"),
            ))

        base_commit = data.get("base_commit", {})
        merge_base_commit = data.get("merge_base_commit", {})

        return RepoSnapshot(
            repository=repo,
            base_ref=base_ref,
            head_ref=head_ref,
            base_sha=base_commit.get("sha"),
            head_sha=merge_base_commit.get("sha") or (commits[-1].sha if commits else None),
            commits=commits,
            diffs=diffs,
            changed_files=changed_files,
        )
