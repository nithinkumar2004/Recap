"""Code Agent: Deterministic Commit & AST Analysis with LLM Semantic Synthesis."""
from __future__ import annotations
import ast
import os
import re
from typing import List, Tuple, Dict, Any, Optional
import httpx

from app.config import settings
from app.models.contracts import (
    CommitInfo,
    FileDiff,
    RepoSnapshot,
    ChangeItem,
    BreakingChange,
    CodeAnalysisResult,
    VersionBump,
)


CONVENTIONAL_REGEX = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\((?P<scope>[a-zA-Z0-9_\-\./]+)\))?"
    r"(?P<breaking>!)?:\s*(?P<subject>.+)$",
    re.MULTILINE
)


class ASTSignatureExtractor(ast.NodeVisitor):
    """Extracts public functions and method signatures from Python code."""
    def __init__(self):
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.classes: Dict[str, List[str]] = {}
        self._current_class = None
        self._function_depth = 0

    def visit_ClassDef(self, node: ast.ClassDef):
        if self._function_depth:
            return
        prev = self._current_class
        self._current_class = f"{prev}.{node.name}" if prev else node.name
        self.classes[self._current_class] = []
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if not self._function_depth:
            self._record_func(node)
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        if not self._function_depth:
            self._record_func(node)
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    def _record_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        if node.name.startswith("_") and not node.name.startswith("__init__"):
            return  # private method

        qualname = f"{self._current_class}.{node.name}" if self._current_class else node.name
        
        args = node.args
        positional = [*args.posonlyargs, *args.args]
        positional_default_start = len(positional) - len(args.defaults)
        parameters = []
        for index, arg in enumerate(args.posonlyargs):
            parameters.append({"name": arg.arg, "kind": "positional_only", "required": index < positional_default_start})
        for index, arg in enumerate(args.args, start=len(args.posonlyargs)):
            parameters.append({"name": arg.arg, "kind": "positional_or_keyword", "required": index < positional_default_start})
        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            parameters.append({"name": arg.arg, "kind": "keyword_only", "required": default is None})
        if args.vararg:
            parameters.append({"name": args.vararg.arg, "kind": "var_positional", "required": False})
        if args.kwarg:
            parameters.append({"name": args.kwarg.arg, "kind": "var_keyword", "required": False})

        argument_names = [parameter["name"] for parameter in parameters]

        self.functions[qualname] = {
            "name": node.name,
            "qualname": qualname,
            "parameters": parameters,
            "positional_order": [arg.arg for arg in positional],
            "has_varargs": args.vararg is not None,
            "has_varkw": args.kwarg is not None,
            "signature": f"{node.name}({', '.join(argument_names)})"
        }
        if self._current_class:
            self.classes[self._current_class].append(qualname)


def detect_ast_breaking_changes(old_code: str, new_code: str, filename: str) -> List[BreakingChange]:
    """Compares two Python source files and deterministically flags signature breaking changes."""
    breaking: List[BreakingChange] = []
    try:
        old_tree = ast.parse(old_code, filename=filename)
        new_tree = ast.parse(new_code, filename=filename)
    except SyntaxError:
        return breaking

    old_extractor = ASTSignatureExtractor()
    old_extractor.visit(old_tree)

    new_extractor = ASTSignatureExtractor()
    new_extractor.visit(new_tree)

    # 1. Check for removed classes
    for cls_name in old_extractor.classes:
        if cls_name not in new_extractor.classes:
            breaking.append(BreakingChange(
                component=filename,
                identifier=cls_name,
                old_signature=f"class {cls_name}",
                new_signature=None,
                impact=f"Class '{cls_name}' was removed or renamed.",
                confidence="HIGH"
            ))

    # 2. Check for removed public functions/methods
    for fn_name, fn_info in old_extractor.functions.items():
        if fn_name not in new_extractor.functions:
            breaking.append(BreakingChange(
                component=filename,
                identifier=fn_name,
                old_signature=fn_info["signature"],
                new_signature=None,
                impact=f"Function/Method '{fn_name}' was removed or renamed.",
                confidence="HIGH"
            ))
            continue

        new_info = new_extractor.functions[fn_name]
        
        # 3. Check for added REQUIRED arguments (breaking for callers)
        old_parameters = {param["name"]: param for param in fn_info["parameters"]}
        new_parameters = {param["name"]: param for param in new_info["parameters"]}
        old_required = {name for name, param in old_parameters.items() if param["required"]}
        new_required = {name for name, param in new_parameters.items() if param["required"]}
        added_required = new_required - old_required

        if added_required:
            breaking.append(BreakingChange(
                component=filename,
                identifier=fn_name,
                old_signature=fn_info["signature"],
                new_signature=new_info["signature"],
                impact=f"New required parameter(s) added: {', '.join(added_required)}. Existing callers without these parameters will fail.",
                confidence="HIGH"
            ))

        # 4. Check for removed parameters
        removed_params = set(old_parameters) - set(new_parameters)
        if removed_params and not new_info["has_varkw"]:
            breaking.append(BreakingChange(
                component=filename,
                identifier=fn_name,
                old_signature=fn_info["signature"],
                new_signature=new_info["signature"],
                impact=f"Parameter(s) removed: {', '.join(removed_params)}. Existing callers passing these arguments will fail.",
                confidence="HIGH"
            ))

        changed_to_keyword_only = [
            name for name in old_parameters.keys() & new_parameters.keys()
            if old_parameters[name]["kind"] in ("positional_only", "positional_or_keyword")
            and new_parameters[name]["kind"] == "keyword_only"
        ]
        if changed_to_keyword_only:
            breaking.append(BreakingChange(
                component=filename,
                identifier=fn_name,
                old_signature=fn_info["signature"],
                new_signature=new_info["signature"],
                impact=f"Parameter(s) moved to keyword-only: {', '.join(sorted(changed_to_keyword_only))}.",
                confidence="HIGH",
            ))

        old_order = [name for name in fn_info["positional_order"] if name in new_parameters]
        new_order = [name for name in new_info["positional_order"] if name in old_parameters]
        if old_order != new_order:
            breaking.append(BreakingChange(
                component=filename,
                identifier=fn_name,
                old_signature=fn_info["signature"],
                new_signature=new_info["signature"],
                impact="Existing positional parameters changed order; positional callers may pass values to different parameters.",
                confidence="HIGH",
            ))

    return breaking


class CodeAgent:
    """Agent responsible for analyzing Git commits, diffs, and AST changes to determine SemVer bump."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OPENROUTER_API_KEY
        self.model = settings.OPENROUTER_MODEL

    def analyze(self, snapshot: RepoSnapshot, repo_dir: Optional[str] = None) -> CodeAnalysisResult:
        """Executes deterministic rules first, then supplements with AST & optional LLM analysis."""
        changes: List[ChangeItem] = []
        breaking_changes: List[BreakingChange] = []
        has_major = False
        has_minor = False
        has_patch = False

        # Step 1: Parse Conventional Commits
        for commit in snapshot.commits:
            match = CONVENTIONAL_REGEX.match(commit.message)
            body_breaking = "BREAKING CHANGE:" in commit.message or "BREAKING-CHANGE:" in commit.message

            if match:
                c_type = match.group("type")
                scope = match.group("scope")
                bang = bool(match.group("breaking"))
                subject = match.group("subject").strip()
                is_breaking = bang or body_breaking

                desc = f"[{scope}] {subject}" if scope else subject
                changes.append(ChangeItem(
                    type=c_type,
                    description=desc,
                    breaking=is_breaking,
                    files=snapshot.changed_files
                ))

                if is_breaking:
                    has_major = True
                    breaking_changes.append(BreakingChange(
                        component="Commit Log",
                        identifier=commit.sha[:7] if commit.sha else "HEAD",
                        impact=f"Commit marked breaking: {desc}",
                        confidence="HIGH"
                    ))
                elif c_type == "feat":
                    has_minor = True
                elif c_type in ("fix", "perf", "refactor"):
                    has_patch = True
            else:
                # Non-conventional commit fallback
                is_breaking = body_breaking
                c_type = "fix" if "fix" in commit.message.lower() else "chore"
                changes.append(ChangeItem(
                    type=c_type,
                    description=commit.message.split("\n")[0].strip() if commit.message else "Update",
                    breaking=is_breaking,
                    files=snapshot.changed_files
                ))
                if is_breaking:
                    has_major = True
                elif "feat" in commit.message.lower():
                    has_minor = True
                else:
                    has_patch = True

        # Step 2: Calculate diff stats
        total_add = sum(d.additions for d in snapshot.diffs)
        total_del = sum(d.deletions for d in snapshot.diffs)

        # Step 3: AST Breaking changes for python diffs
        # 3a. Deep AST check via git show if repo_dir is present and has git
        ast_evaluated_files = set()
        if repo_dir and snapshot.base_ref:
            from app.github.git_service import LocalGitService
            git_svc = LocalGitService(repo_dir=repo_dir)
            for diff in snapshot.diffs:
                fname = diff.filename
                if fname.endswith(".py"):
                    old_filename = diff.previous_filename or fname
                    old_code = git_svc.get_file_content_at_ref(snapshot.base_ref, old_filename)
                    head_ref = snapshot.head_sha or snapshot.head_ref
                    new_code = "" if diff.status == "removed" else git_svc.get_file_content_at_ref(head_ref, fname)

                    if old_code is not None and new_code is not None:
                        deep_breaks = detect_ast_breaking_changes(old_code, new_code, fname)
                        if deep_breaks:
                            has_major = True
                            breaking_changes.extend(deep_breaks)
                        ast_evaluated_files.add(fname)

        # 3b. Fallback to patch-based AST analysis for remaining files
        for diff in snapshot.diffs:
            if diff.filename.endswith(".py") and diff.patch and diff.filename not in ast_evaluated_files:
                ast_breaks = self._analyze_diff_patch(diff.filename, diff.patch)
                if ast_breaks:
                    has_major = True
                    breaking_changes.extend(ast_breaks)

        # Step 4: Determine Version Bump
        if has_major or breaking_changes:
            suggested_bump = VersionBump.MAJOR
            reason = f"Breaking changes detected ({len(breaking_changes)} breaking change(s) found)."
        elif has_minor:
            suggested_bump = VersionBump.MINOR
            reason = "New backward-compatible feature(s) introduced."
        elif has_patch:
            suggested_bump = VersionBump.PATCH
            reason = "Backward-compatible bug fixes or internal refactoring."
        else:
            suggested_bump = VersionBump.NONE
            reason = "Only documentation, chore, or CI changes."

        # Step 5: Optional LLM Semantic Enrichment
        if self.api_key and snapshot.commits:
            try:
                enriched_reason = self._llm_semantic_summary(changes, breaking_changes)
                if enriched_reason:
                    reason = f"{reason} | {enriched_reason}"
            except Exception:
                pass  # Deterministic analysis remains reliable

        return CodeAnalysisResult(
            changes=changes,
            breaking_changes=breaking_changes,
            suggested_bump=suggested_bump,
            reason=reason,
            total_additions=total_add,
            total_deletions=total_del,
            files_changed_count=len(snapshot.changed_files),
        )

    def _analyze_diff_patch(self, filename: str, patch: str) -> List[BreakingChange]:
        """Simple patch parser for function signature changes: extracts -def and +def lines."""
        breaking = []
        old_defs = re.findall(r"^-(?:async\s+)?def\s+([a-zA-Z0-9_]+)\(([^)]*)\)\s*(?:->[^:]+)?\s*:", patch, re.MULTILINE)
        new_defs = re.findall(r"^\+(?:async\s+)?def\s+([a-zA-Z0-9_]+)\(([^)]*)\)\s*(?:->[^:]+)?\s*:", patch, re.MULTILINE)

        old_map = {name: args for name, args in old_defs if not name.startswith("_")}
        new_map = {name: args for name, args in new_defs if not name.startswith("_")}

        for name, old_args_str in old_map.items():
            if name not in new_map:
                breaking.append(BreakingChange(
                    component=filename,
                    identifier=name,
                    old_signature=f"def {name}({old_args_str})",
                    new_signature=None,
                    impact=f"Public function '{name}' was removed or renamed.",
                    confidence="HIGH",
                ))
                continue

            new_args_str = new_map[name]
            old_source = f"def {name}({old_args_str}):\n    pass\n"
            new_source = f"def {name}({new_args_str}):\n    pass\n"
            breaking.extend(detect_ast_breaking_changes(old_source, new_source, filename))
        return breaking

    def _llm_semantic_summary(self, changes: List[ChangeItem], breaking: List[BreakingChange]) -> Optional[str]:
        """Calls OpenRouter LLM for a 1-sentence semantic overview of the change impact."""
        prompt = (
            "Summarize the technical impact of these code changes in one concise sentence:\n"
            f"Changes: {[c.description for c in changes[:10]]}\n"
            f"Breaking: {[b.impact for b in breaking]}"
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 100,
        }
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{settings.OPENROUTER_BASE_URL}/chat/completions", headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
        return None
