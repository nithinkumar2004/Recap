"""Unit tests for LocalGitService and repository snapshot extraction."""
import os
import shutil
import subprocess
import tempfile
import pytest

from app.github.git_service import LocalGitService, EMPTY_TREE_SHA
from app.github import resolve_repository_snapshot
from app.models.contracts import VersionBump


@pytest.fixture
def temp_git_repo():
    """Creates a temporary Git repository with realistic commit history and tags."""
    temp_dir = tempfile.mkdtemp(prefix="git_test_repo_")
    
    def run_cmd(args):
        subprocess.run(
            ["git"] + args,
            cwd=temp_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    try:
        # Initialize Git repo
        run_cmd(["init", "-b", "main"])
        run_cmd(["config", "user.name", "Test Committer"])
        run_cmd(["config", "user.email", "test@example.com"])

        # Initial commit
        file1 = os.path.join(temp_dir, "calculator.py")
        with open(file1, "w", encoding="utf-8") as f:
            f.write("def add(a, b):\n    return a + b\n")

        run_cmd(["add", "calculator.py"])
        run_cmd(["commit", "-m", "chore: initial commit"])
        run_cmd(["tag", "v1.0.0"])

        # Second commit (feature)
        with open(file1, "a", encoding="utf-8") as f:
            f.write("\ndef multiply(a, b):\n    return a * b\n")

        run_cmd(["add", "calculator.py"])
        run_cmd(["commit", "-m", "feat(math): add multiplication support"])

        # Third commit (breaking change)
        file2 = os.path.join(temp_dir, "api.py")
        with open(file2, "w", encoding="utf-8") as f:
            f.write("def process(data, strict=True):\n    return data\n")

        run_cmd(["add", "api.py"])
        run_cmd(["commit", "-m", "feat(api)!: require strict flag in process\n\nBREAKING CHANGE: strict parameter required"])

        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_is_git_repo(temp_git_repo):
    service = LocalGitService(repo_dir=temp_git_repo)
    assert service.is_git_repo() is True

    non_repo_dir = tempfile.mkdtemp(prefix="non_git_")
    try:
        non_service = LocalGitService(repo_dir=non_repo_dir)
        assert non_service.is_git_repo() is False
    finally:
        shutil.rmtree(non_repo_dir, ignore_errors=True)


def test_get_latest_tag_and_commits(temp_git_repo):
    service = LocalGitService(repo_dir=temp_git_repo)
    latest_tag = service.get_latest_tag()
    assert latest_tag == "v1.0.0"

    # Commits between v1.0.0 and HEAD should be 2
    commits = service.get_commits_between(base_ref="v1.0.0", head_ref="HEAD")
    assert len(commits) == 2
    assert "multiplication" in commits[1].message
    assert "require strict flag" in commits[0].message
    assert "BREAKING CHANGE:" in commits[0].message


def test_diff_stats_and_patches(temp_git_repo):
    service = LocalGitService(repo_dir=temp_git_repo)
    diffs, changed = service.get_diff_stats_and_patches(base_ref="v1.0.0", head_ref="HEAD")

    assert "calculator.py" in changed
    assert "api.py" in changed
    assert len(diffs) == 2

    calc_diff = next(d for d in diffs if d.filename == "calculator.py")
    assert calc_diff.additions > 0
    assert calc_diff.patch is not None
    assert "multiply" in calc_diff.patch
    api_diff = next(d for d in diffs if d.filename == "api.py")
    assert api_diff.status == "added"


def test_diff_stats_preserve_renames(temp_git_repo):
    subprocess.run(["git", "mv", "calculator.py", "calculator_service.py"], cwd=temp_git_repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "refactor: rename calculator module"],
        cwd=temp_git_repo, check=True, capture_output=True, text=True,
    )

    diffs, changed = LocalGitService(temp_git_repo).get_diff_stats_and_patches("HEAD^", "HEAD")
    renamed = next(diff for diff in diffs if diff.filename == "calculator_service.py")

    assert "calculator_service.py" in changed
    assert renamed.status == "renamed"
    assert renamed.previous_filename == "calculator.py"


def test_extract_snapshot(temp_git_repo):
    service = LocalGitService(repo_dir=temp_git_repo)
    snapshot = service.extract_snapshot(base_ref="v1.0.0", head_ref="HEAD")

    assert snapshot.base_ref == "v1.0.0"
    assert snapshot.head_ref == "main"
    assert snapshot.head_sha is not None
    assert len(snapshot.commits) == 2
    assert len(snapshot.changed_files) == 2


def test_extract_snapshot_resolves_selected_head_not_current_checkout(temp_git_repo):
    expected_head = subprocess.run(
        ["git", "rev-parse", "v1.0.0"], cwd=temp_git_repo,
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    snapshot = LocalGitService(temp_git_repo).extract_snapshot(base_ref="v1.0.0", head_ref="v1.0.0")

    assert snapshot.head_sha == expected_head
    assert snapshot.changed_files == []


def test_resolve_repository_snapshot_factory(temp_git_repo):
    snapshot, repo_dir = resolve_repository_snapshot(
        target=temp_git_repo,
        base_ref="v1.0.0",
        head_ref="HEAD",
    )
    assert repo_dir == os.path.abspath(temp_git_repo)
    assert snapshot.base_ref == "v1.0.0"
    assert len(snapshot.commits) == 2


def test_resolve_repository_snapshot_accepts_owner_repo_shorthand(monkeypatch):
    expected_snapshot = object()

    class FakeGitHubClient:
        @staticmethod
        def parse_repo_identifier(target):
            return target

        @staticmethod
        def get_latest_tag(repo_id):
            return "v1.2.0"

        @staticmethod
        def compare_commits(owner_repo, base_ref, head_ref):
            assert owner_repo == "some-owner/some-repo"
            assert base_ref == "v1.2.0"
            assert head_ref == "main"
            return expected_snapshot

    monkeypatch.setattr("app.github.GitHubClient", FakeGitHubClient)

    snapshot, repo_dir = resolve_repository_snapshot(target="some-owner/some-repo")

    assert snapshot is expected_snapshot
    assert repo_dir is None
