"""Security Agent: Deterministic Secret, SAST, and Dependency Scanners."""
from __future__ import annotations
import math
import os
import re
from typing import List, Dict, Any, Optional
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from app.models.contracts import (
    SecurityFinding,
    SecurityScanResult,
    RiskLevel,
    RepoSnapshot,
    FileDiff,
)

# Common High-Risk Patterns for Secrets
SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key ID", RiskLevel.CRITICAL),
    (re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?"), "AWS Secret Access Key", RiskLevel.CRITICAL),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"), "GitHub Personal Access Token", RiskLevel.CRITICAL),
    (re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"), "GitHub OAuth Access Token", RiskLevel.CRITICAL),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private Cryptographic Key", RiskLevel.CRITICAL),
    (re.compile(r"(?i)(api[_\-]?key|secret|token|password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]"), "Hardcoded High-Entropy Secret/Key", RiskLevel.HIGH),
]

# SAST Patterns for Security Anti-Patterns
SAST_PATTERNS = [
    (
        re.compile(r"cursor\.execute\s*\(\s*f[\"'].*\{"),
        "Potential SQL Injection: Formatted string in cursor.execute",
        RiskLevel.CRITICAL
    ),
    (
        re.compile(r"(subprocess\.(?:Popen|run|call)\s*\(.*shell\s*=\s*True|os\.system\s*\(.*\{)"),
        "Command Injection: Untrusted shell command execution",
        RiskLevel.CRITICAL
    ),
    (
        re.compile(r"pickle\.(loads|load)\s*\("),
        "Insecure Deserialization: Unsafe pickle deserialization",
        RiskLevel.HIGH
    ),
    (
        re.compile(r"yaml\.load\s*\([^,)]+\)(?!\s*Loader\s*=\s*yaml\.SafeLoader)"),
        "Insecure Deserialization: Unsafe PyYAML load without SafeLoader",
        RiskLevel.HIGH
    ),
    (
        re.compile(r"hashlib\.(md5|sha1)\s*\("),
        "Weak Cryptography: Usage of deprecated MD5/SHA1 hash function",
        RiskLevel.MEDIUM
    ),
    (
        re.compile(r"verify\s*=\s*False"),
        "Insecure Transport: SSL certificate validation disabled",
        RiskLevel.HIGH
    ),
]

# Known Vulnerable Dependency Signatures (Sample CVE DB for OSV scanning)
KNOWN_VULNERABLE_PACKAGES = {
    "requests": {"<2.31.0": ("CVE-2023-32681", RiskLevel.MEDIUM, "Unintended leak of Proxy-Authorization header")},
    "urllib3": {"<2.0.7": ("CVE-2023-45803", RiskLevel.HIGH, "Request body not stripped on redirect")},
    "flask": {"<2.2.5": ("CVE-2023-30861", RiskLevel.HIGH, "High resource usage in multipart/form-data")},
    "cryptography": {"<41.0.6": ("CVE-2023-49083", RiskLevel.HIGH, "NULL-pointer dereference in PKCS7")},
    "django": {"<4.2.8": ("CVE-2023-46695", RiskLevel.CRITICAL, "Denial-of-service in UsernameField")},
    "lodash": {"<4.17.21": ("CVE-2021-23337", RiskLevel.CRITICAL, "Command Injection via template")},
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect high-entropy secrets."""
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy


class SecurityAgent:
    """Deterministic security scanner agent for secrets, SAST, and vulnerable dependencies."""

    def scan(self, snapshot: RepoSnapshot) -> SecurityScanResult:
        findings: List[SecurityFinding] = []

        # 1. Scan diff patches for Secrets & SAST
        for diff in snapshot.diffs:
            if not diff.patch or self._is_generated_file(diff.filename):
                continue

            lines = diff.patch.split("\n")
            for idx, line in enumerate(lines, start=1):
                # Only inspect added lines
                if not line.startswith("+") or line.startswith("+++"):
                    continue

                code_line = line[1:].strip()

                # Gitleaks / Secret Scanning
                secret_finding = self._check_secrets(code_line, diff.filename, idx)
                if secret_finding:
                    findings.append(secret_finding)

                # Semgrep / SAST Scanning
                sast_finding = self._check_sast(code_line, diff.filename, idx)
                if sast_finding:
                    findings.append(sast_finding)

        # 2. Dependency Vulnerability Scanning (OSV scanner simulator)
        for diff in snapshot.diffs:
            if "requirements" in diff.filename or diff.filename == "package.json":
                dep_findings = self._check_dependencies(diff)
                findings.extend(dep_findings)

        findings = self._deduplicate_findings(findings)
        secrets_count = sum(1 for f in findings if f.tool == "gitleaks")
        sast_high = sum(1 for f in findings if f.tool == "semgrep" and f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL))
        sast_med = sum(1 for f in findings if f.tool == "semgrep" and f.severity == RiskLevel.MEDIUM)
        dep_crit = sum(1 for f in findings if f.tool == "osv-scanner" and f.severity == RiskLevel.CRITICAL)
        dep_high = sum(1 for f in findings if f.tool == "osv-scanner" and f.severity == RiskLevel.HIGH)

        return SecurityScanResult(
            findings=findings,
            secrets_count=secrets_count,
            sast_high_count=sast_high,
            sast_medium_count=sast_med,
            dependency_critical_count=dep_crit,
            dependency_high_count=dep_high,
        )

    @staticmethod
    def _is_generated_file(filename: str) -> bool:
        path_parts = filename.replace("\\", "/").lower().split("/")
        return "__pycache__" in path_parts or filename.lower().endswith((".pyc", ".pyo"))

    @staticmethod
    def _deduplicate_findings(findings: List[SecurityFinding]) -> List[SecurityFinding]:
        unique: Dict[tuple, SecurityFinding] = {}
        for finding in findings:
            key = (finding.tool, finding.file_path, finding.line_number, finding.title)
            unique.setdefault(key, finding)
        return list(unique.values())

    def _check_secrets(self, line: str, filename: str, line_no: int) -> Optional[SecurityFinding]:
        for pattern, title, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                # Mask secret snippet for security
                matched_val = match.group(0)
                masked = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:] if len(matched_val) > 10 else "***"
                return SecurityFinding(
                    tool="gitleaks",
                    severity=severity,
                    title=f"Secret Detected: {title}",
                    file_path=filename,
                    line_number=line_no,
                    snippet=masked,
                )
        return None

    def _check_sast(self, line: str, filename: str, line_no: int) -> Optional[SecurityFinding]:
        # Avoid reporting executable-risk patterns in obvious source comments;
        # secret scanning still runs on comments because credentials can leak there.
        if line.lstrip().startswith(("#", "//", "/*", "*")):
            return None
        for pattern, title, severity in SAST_PATTERNS:
            if pattern.search(line):
                return SecurityFinding(
                    tool="semgrep",
                    severity=severity,
                    title=f"SAST Finding: {title}",
                    file_path=filename,
                    line_number=line_no,
                    snippet=line[:120],
                )
        return None

    def _check_dependencies(self, diff: FileDiff) -> List[SecurityFinding]:
        findings = []
        if not diff.patch:
            return findings

        # Parse normal requirements syntax so both pinned and range-based
        # dependencies can be compared against known fixed versions.
        for line in diff.patch.split("\n"):
            if not line.startswith("+") or line.startswith("+++"):
                continue
            line_content = line[1:].strip()
            if not line_content or line_content.startswith(("#", "-")):
                continue
            try:
                requirement = Requirement(line_content.split(";", 1)[0].strip())
            except InvalidRequirement:
                continue

            pkg_name = requirement.name.lower().replace("_", "-")
            rules = KNOWN_VULNERABLE_PACKAGES.get(pkg_name)
            if not rules:
                continue
            for rule_ver, (cve_id, severity, description) in rules.items():
                fixed_version = Version(rule_ver.removeprefix("<"))
                if self._requirement_may_include_vulnerable_version(requirement, fixed_version):
                    findings.append(SecurityFinding(
                        tool="osv-scanner",
                        severity=severity,
                        title=f"Potentially vulnerable dependency: {line_content} ({cve_id})",
                        file_path=diff.filename,
                        snippet=f"{description} (fixed in {fixed_version}; affected: {rule_ver})",
                    ))
        return findings

    @staticmethod
    def _requirement_may_include_vulnerable_version(requirement: Requirement, fixed_version: Version) -> bool:
        """Return true unless the declared specifier proves the package is fixed."""
        if not requirement.specifier:
            return True

        exact_versions = [specifier.version for specifier in requirement.specifier if specifier.operator == "=="]
        if exact_versions:
            try:
                return any(Version(version) < fixed_version for version in exact_versions)
            except InvalidVersion:
                return True

        minimum_versions = [
            specifier.version for specifier in requirement.specifier
            if specifier.operator in (">=", ">")
        ]
        if minimum_versions:
            try:
                highest_minimum = max(Version(version) for version in minimum_versions)
                return highest_minimum < fixed_version
            except InvalidVersion:
                return True
        return True
