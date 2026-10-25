"""Translators: one small function per scanner, raw output in, `Finding` list out.

LESSON 2: this file is the "bridge" in its simplest form. Each function knows how
ONE tool talks, and converts it to the common `Finding` shape from models.py.

LESSON 3 (severity mapping): tools do not agree on severity. Trivy says HIGH,
Semgrep says ERROR, Gitleaks says nothing at all. We choose a mapping once, here,
in plain sight, so the rest of the system can treat severity uniformly. You can
change these choices; they are decisions, not facts.

LESSON 5 (never copy secrets): Gitleaks puts the actual leaked secret in its output.
We deliberately DO NOT copy it into our findings. Reports get emailed, pasted into
tickets and uploaded to dashboards. A scanner report that repeats the secret just
creates a second leak.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from .models import Finding


def _clean_path(path: str, root: str = ".") -> str:
    """Make every path look the same: relative to the scanned folder, no './'."""
    if os.path.isabs(path):
        path = os.path.relpath(path, os.path.abspath(root))
    return os.path.normpath(path).replace(os.sep, "/")


# ---------------------------------------------------------------- Gitleaks
def parse_gitleaks(data: Any, root: str = ".") -> list[Finding]:
    """Gitleaks JSON is a list of leaks. An empty or missing report means none."""
    findings = []
    for item in data or []:
        findings.append(
            Finding(
                tool="gitleaks",
                category="secret",
                rule_id=item.get("RuleID", "unknown"),
                # Gitleaks has no severity. A leaked credential is treated as HIGH.
                severity="high",
                title=item.get("Description") or "Hardcoded secret",
                file=_clean_path(item.get("File", "?"), root),
                line=item.get("StartLine") or None,
                description="A credential-like value is stored in source code. "
                "(The value itself is intentionally left out of this report.)",
                fix="Revoke and rotate the secret, then load it from an environment "
                "variable or a secrets manager instead.",
            )
        )
    return findings


# ----------------------------------------------------------------- Semgrep
_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep(data: Any, root: str = ".") -> list[Finding]:
    """Semgrep JSON has a "results" list, one entry per matched code pattern."""
    findings = []
    for item in (data or {}).get("results", []):
        extra = item.get("extra", {})
        cwe = extra.get("metadata", {}).get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)
        findings.append(
            Finding(
                tool="semgrep",
                category="code",
                rule_id=item.get("check_id", "unknown"),
                severity=_SEMGREP_SEVERITY.get(extra.get("severity", ""), "low"),
                # The last part of the long rule id reads like a name.
                title=item.get("check_id", "unknown").split(".")[-1].replace("-", " "),
                file=_clean_path(item.get("path", "?"), root),
                line=(item.get("start") or {}).get("line"),
                description=f"Weakness type: {cwe}." if cwe else "",
                # Semgrep rules explain the remedy in their message, so we reuse it.
                fix=extra.get("message", ""),
            )
        )
    return findings


# ------------------------------------------------------------------- Trivy
_TRIVY_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def parse_trivy(data: Any, root: str = ".") -> list[Finding]:
    """Trivy JSON groups results per file ("Target"). Each group can hold
    vulnerable libraries ("Vulnerabilities") and bad settings ("Misconfigurations").
    """
    findings = []
    for result in (data or {}).get("Results") or []:
        target = _clean_path(result.get("Target", "?"), root)

        for vuln in result.get("Vulnerabilities") or []:
            fixed: Optional[str] = vuln.get("FixedVersion")
            findings.append(
                Finding(
                    tool="trivy",
                    category="dependency",
                    rule_id=vuln.get("VulnerabilityID", "unknown"),
                    severity=_TRIVY_SEVERITY.get(vuln.get("Severity", ""), "info"),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                    file=target,
                    package=vuln.get("PkgName", ""),
                    description=f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} "
                    f"is affected. {vuln.get('PrimaryURL', '')}".strip(),
                    fix=f"Upgrade {vuln.get('PkgName')} to {fixed} or newer."
                    if fixed
                    else "No fixed version is published yet; consider an alternative.",
                )
            )

        for mis in result.get("Misconfigurations") or []:
            cause = mis.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    tool="trivy",
                    category="config",
                    rule_id=mis.get("ID", "unknown"),
                    severity=_TRIVY_SEVERITY.get(mis.get("Severity", ""), "info"),
                    title=mis.get("Title", "Misconfiguration"),
                    file=target,
                    line=cause.get("StartLine") or None,
                    description=mis.get("Description", ""),
                    fix=mis.get("Resolution", ""),
                )
            )
    return findings


# One lookup table, so the runner never needs an if/else chain per tool.
ADAPTERS = {
    "gitleaks": parse_gitleaks,
    "semgrep": parse_semgrep,
    "trivy": parse_trivy,
}
