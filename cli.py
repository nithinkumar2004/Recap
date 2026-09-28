"""Release Captain CLI: Execute autonomous agentic release evaluations on any Git project."""
from __future__ import annotations
import argparse
import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt

from app.config import settings
from app.credentials import load_credentials, save_credentials
from app.models.contracts import (
    RepoSnapshot,
    CommitInfo,
    FileDiff,
    TestRunResult,
    VersionBump,
)
from app.core.orchestrator import ReleaseOrchestrator
from app.release.executor import ReleaseExecutor
from app.github import resolve_repository_snapshot, LocalGitService, GitCommandError

console = Console()


def ensure_credentials() -> None:
    """Load or interactively collect the API credentials required for live runs."""
    saved = load_credentials()
    prompted: dict[str, str] = {}
    required = (
        ("OPENROUTER_API_KEY", "OpenRouter API key", settings.OPENROUTER_API_KEY),
        ("GITHUB_TOKEN", "GitHub access token", settings.GITHUB_TOKEN),
    )

    for setting_name, prompt_label, configured_value in required:
        value = configured_value or saved.get(setting_name, "")
        while not value:
            value = Prompt.ask(f"Enter your {prompt_label}", password=True).strip()
            if not value:
                console.print("[yellow]A non-empty credential is required.[/yellow]")
        setattr(settings, setting_name, value)
        if not configured_value and value != saved.get(setting_name):
            prompted[setting_name] = value

    if prompted:
        try:
            save_credentials(prompted)
            console.print("[dim]Credentials saved in your private user configuration directory.[/dim]")
        except OSError as error:
            console.print(f"[yellow]Credentials are available for this run but could not be saved: {error}[/yellow]")


def log_pipeline_event(phase: str, msg: str):
    """Rich colored console logger for agent lifecycle phases."""
    color = "cyan"
    if "CODE" in phase:
        color = "blue"
    elif "TEST" in phase:
        color = "green"
    elif "SECURITY" in phase:
        color = "yellow"
    elif "RISK" in phase:
        color = "magenta"
    elif "PLANNER" in phase:
        color = "bright_cyan"
    console.print(f"[{color}][{phase}][/{color}] {msg}")


def execute_release_pipeline(
    snapshot: RepoSnapshot,
    repo_dir: str | None = None,
    current_version: str | None = None,
    precomputed_tests: TestRunResult | None = None,
    skip_tests: bool = False,
    approve_flag: bool = False,
    reject_flag: bool = False,
):
    """Runs the full agent pipeline on a RepoSnapshot and presents interactive results."""
    effective_version = current_version or snapshot.base_ref or "v1.0.0"

    orchestrator = ReleaseOrchestrator(event_callback=log_pipeline_event)

    console.print("\n[bold]Starting Staged Agent Pipeline...[/bold]\n")

    # If skipping tests or precomputed provided
    test_run = precomputed_tests
    if skip_tests and test_run is None:
        test_run = TestRunResult(
            framework="skipped",
            total=0,
            passed=0,
            failed=0,
            skipped=0,
            duration_seconds=0.0,
        )

    report = orchestrator.execute_pipeline(
        snapshot=snapshot,
        current_version=effective_version,
        repo_dir=repo_dir,
        precomputed_tests=test_run,
    )

    # Display Dashboard Summary
    console.print("\n" + "=" * 60)
    console.print(Panel.fit(
        f"[bold white]REPOSITORY:[/bold white] {report.repository}\n"
        f"[bold white]CURRENT VERSION:[/bold white] {report.release_plan.current_version}\n"
        f"[bold green]PROPOSED VERSION:[/bold green] [bold yellow]{report.release_plan.proposed_version}[/bold yellow] ({report.release_plan.bump_type.value.upper()})\n"
        f"[bold white]STATUS / RECOMMENDATION:[/bold white] [bold cyan]{report.release_plan.recommendation.value.upper()}[/bold cyan]",
        title="[bold yellow]RELEASE CANDIDATE DECISION[/bold yellow]"
    ))

    # Changes Table
    changes_table = Table(title="Classified Code Changes (Code Agent)")
    changes_table.add_column("Type", style="cyan")
    changes_table.add_column("Description", style="white")
    changes_table.add_column("Breaking?", style="red")

    for chg in report.code_analysis.changes:
        changes_table.add_row(
            chg.type,
            chg.description,
            "YES (MAJOR)" if chg.breaking else "No"
        )
    console.print(changes_table)

    # Breaking Changes Table
    if report.code_analysis.breaking_changes:
        bc_table = Table(title="Detected Breaking Changes (AST + Commit)", style="red")
        bc_table.add_column("Component", style="yellow")
        bc_table.add_column("Identifier", style="bold white")
        bc_table.add_column("Impact", style="white")
        for bc in report.code_analysis.breaking_changes:
            bc_table.add_row(bc.component, bc.identifier, bc.impact)
        console.print(bc_table)

    # Risk Engine Table
    risk_color = (
        "green" if report.risk_evaluation.level.value == "LOW"
        else "yellow" if report.risk_evaluation.level.value == "MEDIUM"
        else "red"
    )
    risk_table = Table(
        title=f"Explainable Risk Engine (Score: {report.risk_evaluation.score} - [{risk_color}]{report.risk_evaluation.level.value}[/{risk_color}])"
    )
    risk_table.add_column("Weight", style="magenta")
    risk_table.add_column("Factor", style="bold white")
    risk_table.add_column("Description", style="white")

    for f in report.risk_evaluation.factors:
        risk_table.add_row(f"+{f.weight}", f.name, f.description)
    console.print(risk_table)

    # Verification Health
    if report.test_results.framework == "skipped":
        test_str = "Skipped (--skip-tests)"
    elif report.test_results.total == 0 and not report.test_results.execution_error:
        test_str = "No tests discovered (0 tests run)"
    else:
        test_str = f"{report.test_results.passed}/{report.test_results.total} passed in {report.test_results.duration_seconds}s"
    test_label = "[yellow][!] Tests:[/yellow]" if report.test_results.total == 0 else "[green][PASS] Tests:[/green]"
    console.print(Panel(
        f"{test_label} {test_str}\n"
        f"[yellow][!] Secrets Detected:[/yellow] {report.security_results.secrets_count}\n"
        f"[yellow][!] SAST High Findings:[/yellow] {report.security_results.sast_high_count}\n"
        f"[green][OK] Critical CVEs:[/green] {report.security_results.dependency_critical_count}",
        title="Verification & Security Health"
    ))
    if report.test_results.execution_error:
        console.print(Panel(
            report.test_results.execution_error[-3000:],
            title="Test Runner Diagnostic (execution was not verified)",
            border_style="red",
        ))
    elif report.test_results.failure_details:
        failures_text = "\n".join(
            f"• {case.name}: {case.error_message or 'failed'}"
            for case in report.test_results.failure_details[:20]
        )
        console.print(Panel(failures_text, title="Failed Test Diagnostics", border_style="red"))

    # Release Notes
    console.print(Panel(
        Markdown(report.release_plan.release_notes_md),
        title="Generated Release Notes (Release Planner Agent)",
        border_style="cyan"
    ))

    # --- Interactive Approval / Rejection Gate ---
    console.print("\n[bold yellow]═══ HUMAN APPROVAL GATE ═══[/bold yellow]")

    if approve_flag:
        decision = "approve"
        actor = "ci-bot"
        reason = None
    elif reject_flag:
        decision = "reject"
        actor = "ci-bot"
        reason = "Rejected via automated CI flag"
    else:
        decision = Prompt.ask(
            "[bold white]Enter decision[/bold white]",
            choices=["approve", "reject", "cancel"],
            default="approve"
        )
        if decision == "cancel":
            console.print("[yellow]Release evaluation cancelled. No action taken.[/yellow]")
            return

        actor = Prompt.ask("[bold white]Enter approver/reviewer name[/bold white]", default="lead-maintainer")
        reason = None
        if decision == "reject":
            reason = Prompt.ask(
                "[bold white]Enter rejection reason[/bold white]",
                default="High risk score requires additional staging verification"
            )

    executor = ReleaseExecutor()
    result = executor.execute(
        report=report,
        decision=decision.upper(),
        actor=actor,
        reason=reason,
        repo_dir=repo_dir,
    )

    # Display Execution Result & Audit Trail
    status_color = "bold green" if result.success else "bold red"
    console.print("\n" + "=" * 60)
    console.print(Panel.fit(
        f"[bold white]STATUS:[/bold white] [{status_color}]{result.status}[/{status_color}]\n"
        f"[bold white]MESSAGE:[/bold white] {result.message}\n"
        + (f"[bold white]RELEASE ARTIFACT:[/bold white] {result.release_artifact_path}\n" if result.release_artifact_path else ""),
        title="[bold yellow]RELEASE EXECUTION RESULT[/bold yellow]"
    ))

    # Audit Trail Table
    audit_table = Table(title="Immutable Audit Trail (Phase 9 & 10)", style="cyan")
    audit_table.add_column("Timestamp", style="dim")
    audit_table.add_column("Actor", style="yellow")
    audit_table.add_column("Action", style="bold white")
    audit_table.add_column("Status", style="green")
    audit_table.add_column("Details", style="white")

    for ev in result.audit_trail:
        st_color = "green" if ev.status == "SUCCESS" else "red"
        audit_table.add_row(
            ev.timestamp,
            ev.actor,
            ev.action,
            f"[{st_color}]{ev.status}[/{st_color}]",
            ev.details,
        )
    console.print(audit_table)
    console.print("")


def run_demo(approve_flag: bool = False, reject_flag: bool = False):
    """Runs simulated demo release pipeline."""
    console.print(Panel.fit(
        "[bold cyan]RELEASE CAPTAIN[/bold cyan] - Autonomous Agentic Release Engineering Platform",
        subtitle="Simulated Demo Mode"
    ))

    snapshot = RepoSnapshot(
        repository="myorg/payment-service",
        base_ref="v1.2.0",
        head_ref="main",
        base_sha="a1b2c3d4e5f6",
        head_sha="f6e5d4c3b2a1",
        commits=[
            CommitInfo(
                sha="7f8b9a10c11d12e13f14a15b16c17d18e19f20a1",
                message="feat(auth): add OAuth2 login and JWT session handling",
                author="Alice Dev",
            ),
            CommitInfo(
                sha="8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b",
                message="fix(payments): resolve timeout in payment processing gateway",
                author="Bob Eng",
            ),
            CommitInfo(
                sha="9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
                message="feat(billing)!: require currency parameter in charge API\n\nBREAKING CHANGE: charge() now requires currency argument",
                author="Alice Dev",
            ),
            CommitInfo(
                sha="0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
                message="chore: update requirements.txt with latest packages",
                author="Charlie Ops",
            ),
        ],
        changed_files=[
            "src/auth/oauth.py",
            "src/payments/processor.py",
            "migrations/003_add_currency.sql",
            "requirements.txt",
        ],
        diffs=[
            FileDiff(
                filename="src/auth/oauth.py",
                additions=145,
                deletions=12,
                patch="""@@ -10,4 +10,25 @@
+def setup_oauth(app, client_id, client_secret):
+    # Configure OAuth2 client
+    pass
"""
            ),
            FileDiff(
                filename="src/payments/processor.py",
                additions=30,
                deletions=15,
                patch="""@@ -40,4 +40,5 @@
-def charge(user_id, amount):
+def charge(user_id, amount, currency):
+    # Added currency validation
     pass
"""
            ),
            FileDiff(
                filename="requirements.txt",
                additions=3,
                deletions=2,
                patch="""@@ -1,2 +1,3 @@
-requests==2.28.0
+requests==2.31.0
+cryptography==42.0.0
"""
            ),
            FileDiff(
                filename="migrations/003_add_currency.sql",
                additions=12,
                deletions=0,
                patch="""+ALTER TABLE transactions ADD COLUMN currency VARCHAR(3) NOT NULL DEFAULT 'USD';"""
            ),
        ]
    )

    test_run = TestRunResult(
        framework="pytest",
        total=147,
        passed=147,
        failed=0,
        skipped=0,
        duration_seconds=18.4,
    )

    execute_release_pipeline(
        snapshot=snapshot,
        current_version="v1.2.0",
        precomputed_tests=test_run,
        approve_flag=approve_flag,
        reject_flag=reject_flag,
    )


def run_live(
    repo_target: str,
    base_ref: str | None = None,
    head_ref: str = "HEAD",
    skip_tests: bool = False,
    approve_flag: bool = False,
    reject_flag: bool = False,
):
    """Extracts live Git snapshot from target project and runs the autonomous release pipeline."""
    console.print(Panel.fit(
        f"[bold cyan]RELEASE CAPTAIN[/bold cyan] - Autonomous Agentic Release Engineering Platform\n"
        f"[dim]Analyzing target project: {repo_target}[/dim]",
        subtitle="Live Git Repository Analysis"
    ))

    console.print(f"[bold blue][GIT_DISCOVERY][/bold blue] Inspecting repository at: {os.path.abspath(repo_target) if os.path.exists(repo_target) else repo_target}")

    try:
        snapshot, repo_dir = resolve_repository_snapshot(
            target=repo_target,
            base_ref=base_ref,
            head_ref=head_ref,
        )
    except GitCommandError as e:
        console.print(f"[bold red][ERROR][/bold red] Failed to read Git repository: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Unexpected error resolving repository: {e}")
        sys.exit(1)

    console.print(f"[bold green][GIT_SNAPSHOT][/bold green] Repository: [bold]{snapshot.repository}[/bold]")
    console.print(f"[bold green][GIT_SNAPSHOT][/bold green] Range: {snapshot.base_ref} ... {snapshot.head_ref}")
    console.print(f"[bold green][GIT_SNAPSHOT][/bold green] Commits found: {len(snapshot.commits)}, Files changed: {len(snapshot.changed_files)}")

    if not snapshot.commits and not snapshot.changed_files:
        console.print("[yellow][!] No changes or commits detected in this Git range. Nothing to release.[/yellow]")
        return

    execute_release_pipeline(
        snapshot=snapshot,
        repo_dir=repo_dir,
        current_version=snapshot.base_ref,
        skip_tests=skip_tests,
        approve_flag=approve_flag,
        reject_flag=reject_flag,
    )


def run_rollback(version_tag: str, repo_target: str):
    """Interactively remove a Release Captain local tag and matching notes file."""
    git_service = LocalGitService(repo_dir=repo_target)
    if not git_service.is_git_repo():
        console.print("[bold red][ERROR][/bold red] Rollback requires a local Git repository.")
        raise SystemExit(1)

    confirm = Prompt.ask(
        f"Remove Release Captain tag '{version_tag}' and its matching local release notes?",
        choices=["yes", "no"],
        default="no",
    )
    if confirm != "yes":
        console.print("[yellow]Rollback cancelled; no changes made.[/yellow]")
        return

    actor = Prompt.ask("Approver/reviewer name", default="release-lead")
    result = ReleaseExecutor().rollback(version_tag, git_service.repo_dir, actor=actor)
    color = "green" if result.success else "red"
    console.print(Panel.fit(
        f"[bold]STATUS:[/bold] [{color}]{result.status}[/{color}]\n{result.message}",
        title="Release Rollback",
    ))
    for event in result.audit_trail:
        console.print(f"[{event.status}] {event.action}: {event.details}")
    if not result.success:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Release Captain: Autonomous AI Release Engineering Platform for any Git project"
    )
    parser.add_argument(
        "--repo", "-r",
        type=str,
        default=None,
        help="Path to target Git repository (e.g. '.' or '../other-project') or GitHub repo ('owner/repo')",
    )
    parser.add_argument(
        "project_directory",
        nargs="?",
        help="Optional project directory; defaults to the current Git repository",
    )
    parser.add_argument(
        "--base", "-b",
        type=str,
        default=None,
        help="Base tag or commit SHA to compare from (default: auto-detected latest tag or initial commit)",
    )
    parser.add_argument(
        "--head",
        type=str,
        default="HEAD",
        help="Head reference (branch, tag, or commit SHA, default: HEAD)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the simulated demo with mock payment-service commits",
    )
    parser.add_argument(
        "--skip-tests", "--no-tests",
        dest="skip_tests",
        action="store_true",
        help="Skip running tests in the target project",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Automatically approve the release without interactive prompt (for CI/CD)",
    )
    parser.add_argument(
        "--reject",
        action="store_true",
        help="Automatically reject the release without interactive prompt (for CI/CD)",
    )
    parser.add_argument(
        "--rollback",
        metavar="TAG",
        help="Interactively remove a Release Captain local tag and its matching release notes",
    )

    args = parser.parse_args()

    if args.rollback:
        if args.demo:
            parser.error("--rollback cannot be combined with --demo")
        if args.repo and args.project_directory:
            parser.error("provide the project directory either positionally or with --repo, not both")
        run_rollback(args.rollback, args.repo or args.project_directory or ".")
        return

    # Determine whether to run live or demo
    if args.demo:
        run_demo(approve_flag=args.approve, reject_flag=args.reject)
        return

    if args.repo and args.project_directory:
        parser.error("provide the project directory either positionally or with --repo, not both")

    repo_target = args.repo or args.project_directory
    if repo_target:
        ensure_credentials()
        run_live(
            repo_target=repo_target,
            base_ref=args.base,
            head_ref=args.head,
            skip_tests=args.skip_tests,
            approve_flag=args.approve,
            reject_flag=args.reject,
        )
        return

    # Check if current directory has a git repo
    git_check = LocalGitService(repo_dir=".")
    if git_check.is_git_repo():
        ensure_credentials()
        run_live(
            repo_target=".",
            base_ref=args.base,
            head_ref=args.head,
            skip_tests=args.skip_tests,
            approve_flag=args.approve,
            reject_flag=args.reject,
        )
    else:
        console.print("[bold red][ERROR][/bold red] Current directory is not a Git repository.")
        console.print("[dim]Run `recap <project-directory>` or use `recap --demo` for the simulated example.[/dim]")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
