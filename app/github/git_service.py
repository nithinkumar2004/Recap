"""Local Git Service: Deterministic extraction of commits, diffs, tags, and code from local Git repositories."""
from __future__ import annotations
import json
import os
import re
import subprocess
from typing import List, Optional, Tuple, Dict, Any

from app.models.contracts import RepoSnapshot, CommitInfo, FileDiff


EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class GitCommandError(Exception):
    """Raised when a Git command execution fails."""
    pass


class LocalGitService:
    """Service to interact with and extract release engineering data from a local Git repository."""

    def __init__(self, repo_dir: str = "."):
        self.repo_dir = os.path.abspath(repo_dir)

    def _run_git(self, args: List[str], check: bool = True) -> str:
        """Executes a git command inside the target repository directory."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=check,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
            raise GitCommandError(f"Git command failed: git {' '.join(args)} (Error: {err_msg})") from e
        except FileNotFoundError as e:
            raise GitCommandError("git executable not found in system PATH.") from e

    def is_git_repo(self) -> bool:
        """Checks if the directory is inside a valid Git work tree."""
        try:
            res = self._run_git(["rev-parse", "--is-inside-work-tree"], check=False)
            return res.lower() == "true"
        except Exception:
            return False

    def get_repo_root(self) -> str:
        """Returns the absolute top-level directory of the Git repository."""
        return self._run_git(["rev-parse", "--show-toplevel"])

    def get_repository_name(self) -> str:
        """
        Infers repository name from remote origin URL or directory name.
        Example: 'git@github.com:myorg/payment-service.git' -> 'myorg/payment-service'
        """
        try:
            remote_url = self._run_git(["config", "--get", "remote.origin.url"], check=False)
            if remote_url:
                # Handle SSH format: git@github.com:org/repo.git
                ssh_match = re.search(r"[:/]([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+?)(?:\.git)?$", remote_url)
                if ssh_match:
                    return ssh_match.group(1)
        except Exception:
            pass

        # Fallback to directory name
        return os.path.basename(self.repo_dir) or "local-project"

    def get_current_head_sha(self) -> str:
        """Returns the full 40-character SHA of HEAD."""
        return self._run_git(["rev-parse", "HEAD"])

    def get_current_branch(self) -> str:
        """Returns current branch name or 'HEAD' if detached."""
        branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], check=False)
        return branch if branch else "HEAD"

    def get_all_tags(self) -> List[str]:
        """Returns all tags sorted by creation date (newest first)."""
        output = self._run_git(["tag", "-l", "--sort=-creatordate"], check=False)
        if not output:
            return []
        return [t.strip() for t in output.splitlines() if t.strip()]

    def get_latest_tag(self) -> Optional[str]:
        """
        Finds the most recent tag reachable from HEAD.
        Falls back to the most recent tag overall.
        """
        try:
            tag = self._run_git(["describe", "--tags", "--abbrev=0"], check=False)
            if tag and tag.strip():
                return tag.strip()
        except Exception:
            pass

        all_tags = self.get_all_tags()
        return all_tags[0] if all_tags else None

    def detect_project_version(self) -> str:
        """
        Infers current version from git tags or project metadata files.
        Checks git tags first, then package.json, pyproject.toml, Cargo.toml.
        """
        latest_tag = self.get_latest_tag()
        if latest_tag:
            return latest_tag

        root = self.repo_dir
        # Node.js
        pkg_json = os.path.join(root, "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "version" in data:
                        return f"v{data['version']}" if not data["version"].startswith("v") else data["version"]
            except Exception:
                pass

        # Python pyproject.toml
        pyproject = os.path.join(root, "pyproject.toml")
        if os.path.exists(pyproject):
            try:
                with open(pyproject, "r", encoding="utf-8") as f:
                    content = f.read()
                    m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if m:
                        ver = m.group(1)
                        return f"v{ver}" if not ver.startswith("v") else ver
            except Exception:
                pass

        # Rust Cargo.toml
        cargo = os.path.join(root, "Cargo.toml")
        if os.path.exists(cargo):
            try:
                with open(cargo, "r", encoding="utf-8") as f:
                    content = f.read()
                    m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if m:
                        ver = m.group(1)
                        return f"v{ver}" if not ver.startswith("v") else ver
            except Exception:
                pass

        return "v0.1.0"

    def get_initial_commit(self) -> str:
        """Returns the first commit SHA of the repository."""
        res = self._run_git(["rev-list", "--max-parents=0", "HEAD"], check=False)
        lines = res.splitlines()
        return lines[-1].strip() if lines else "HEAD"

    def get_commits_between(self, base_ref: Optional[str] = None, head_ref: str = "HEAD") -> List[CommitInfo]:
        """
        Extracts commits between base_ref and head_ref.
        If base_ref is None or does not exist, fetches all commits up to head_ref.
        """
        delimiter = "<!||!>"
        record_sep = "<!##RECORD_END##!>"
        format_str = f"%H{delimiter}%an{delimiter}%ad{delimiter}%s{delimiter}%b{record_sep}"

        range_arg = f"{base_ref}..{head_ref}" if base_ref else head_ref

        try:
            output = self._run_git(["log", f"--pretty=format:{format_str}", "--date=iso", range_arg])
        except GitCommandError:
            # If range failed (e.g. base_ref not found or shallow), fallback to head_ref only
            output = self._run_git(["log", f"--pretty=format:{format_str}", "--date=iso", head_ref], check=False)

        commits: List[CommitInfo] = []
        if not output:
            return commits

        records = output.split(record_sep)
        for rec in records:
            rec = rec.strip()
            if not rec:
                continue
            parts = rec.split(delimiter)
            if len(parts) >= 4:
                sha = parts[0].strip()
                author = parts[1].strip()
                date = parts[2].strip()
                subject = parts[3].strip()
                body = parts[4].strip() if len(parts) > 4 else ""

                full_message = f"{subject}\n\n{body}".strip() if body else subject

                commits.append(CommitInfo(
                    sha=sha,
                    message=full_message,
                    author=author,
                    date=date,
                ))

        return commits

    def get_diff_stats_and_patches(
        self, base_ref: Optional[str] = None, head_ref: str = "HEAD"
    ) -> Tuple[List[FileDiff], List[str]]:
        """
        Calculates diff stats and individual file unified patches between base_ref and head_ref.
        """
        # Determine base comparison target
        target_base = base_ref
        if not target_base:
            # Diff from empty tree (all files)
            target_base = EMPTY_TREE_SHA

        range_arg = f"{target_base}..{head_ref}"

        # Capture status and rename metadata separately: numstat alone loses
        # whether a file was added, removed, renamed, or simply modified.
        status_output = self._run_git(
            ["diff", "--name-status", "--find-renames", range_arg], check=False
        )
        file_status: Dict[str, Dict[str, Optional[str]]] = {}
        for line in status_output.splitlines():
            fields = line.split("\t")
            if len(fields) >= 3 and fields[0].startswith("R"):
                file_status[fields[2]] = {"status": "renamed", "previous_filename": fields[1]}
            elif len(fields) >= 2:
                code = fields[0]
                status = {"A": "added", "D": "removed"}.get(code[:1], "modified")
                file_status[fields[1]] = {"status": status, "previous_filename": None}

        # 1. Numstat: additions, deletions, filename
        try:
            numstat_out = self._run_git(["diff", "--numstat", "--find-renames", range_arg])
        except GitCommandError:
            # Fallback to diffing against root or HEAD~1
            numstat_out = self._run_git(["diff", "--numstat", "HEAD~1..HEAD"], check=False)
            range_arg = "HEAD~1..HEAD"

        file_stats: Dict[str, Dict[str, int]] = {}

        for line in numstat_out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                raw_add, raw_del, fname = parts[0], parts[1], parts[2]
                if " => " in fname:
                    old_name, fname = fname.split(" => ", 1)
                    file_status.setdefault(fname, {"status": "renamed", "previous_filename": old_name})
                adds = int(raw_add) if raw_add.isdigit() else 0
                dels = int(raw_del) if raw_del.isdigit() else 0
                file_stats[fname] = {"additions": adds, "deletions": dels}

        changed_files = list(file_status) or list(file_stats)

        # 2. Extract patches per file
        diffs: List[FileDiff] = []
        for fname in changed_files:
            patch = None
            try:
                patch_out = self._run_git(["diff", "-p", range_arg, "--", fname], check=False)
                if patch_out.strip():
                    patch = patch_out
            except Exception:
                pass

            stats = file_stats.get(fname, {"additions": 0, "deletions": 0})
            diffs.append(FileDiff(
                filename=fname,
                status=file_status.get(fname, {}).get("status") or "modified",
                previous_filename=file_status.get(fname, {}).get("previous_filename"),
                additions=stats["additions"],
                deletions=stats["deletions"],
                patch=patch,
            ))

        return diffs, changed_files

    def get_file_content_at_ref(self, ref: str, filename: str) -> Optional[str]:
        """Fetches the content of a file at a specific Git ref (e.g. 'v1.0.0:src/main.py')."""
        try:
            return self._run_git(["show", f"{ref}:{filename}"])
        except Exception:
            return None

    def extract_snapshot(
        self,
        base_ref: Optional[str] = None,
        head_ref: str = "HEAD",
        repository_name: Optional[str] = None,
    ) -> RepoSnapshot:
        """
        Creates a complete RepoSnapshot by reading the live local Git repository.
        """
        if not self.is_git_repo():
            raise GitCommandError(f"Directory '{self.repo_dir}' is not a valid Git repository.")

        repo_name = repository_name or self.get_repository_name()
        resolved_head = self._run_git(["rev-parse", f"{head_ref}^{{commit}}"], check=False)
        if not resolved_head:
            raise GitCommandError(f"Could not resolve analyzed head ref '{head_ref}'.")
        head_sha = resolved_head

        # If base_ref not supplied, find latest tag or first commit
        actual_base = base_ref
        if not actual_base:
            actual_base = self.get_latest_tag()

        # Base SHA
        base_sha = None
        if actual_base:
            try:
                base_sha = self._run_git(["rev-parse", f"{actual_base}^{{commit}}"], check=False)
            except Exception:
                base_sha = None

        commits = self.get_commits_between(base_ref=actual_base, head_ref=head_ref)
        diffs, changed_files = self.get_diff_stats_and_patches(base_ref=actual_base, head_ref=head_ref)

        effective_base_label = actual_base or self.detect_project_version()
        effective_head_label = self.get_current_branch() if head_ref == "HEAD" else head_ref

        return RepoSnapshot(
            repository=repo_name,
            base_ref=effective_base_label,
            head_ref=effective_head_label,
            base_sha=base_sha,
            head_sha=head_sha,
            commits=commits,
            diffs=diffs,
            changed_files=changed_files,
        )
