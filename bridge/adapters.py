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


# ----------------------------------------------------------------- zizmor
_ZIZMOR_SEVERITY = {"high": "high", "medium": "medium", "low": "low",
                    "informational": "info", "unknown": "info"}


def parse_zizmor(data: Any, root: str = ".") -> list[Finding]:
    """zizmor checks CI/CD pipeline files (GitHub Actions workflows) for unsafe setups.

    Its JSON is a flat list. Each item has an `ident` (the rule name), a `desc`, a
    `url` to its documentation, a severity under `determinations`, and `locations`
    saying which file and line. Two details worth knowing, both from zizmor's docs:
    line numbers in this format start at 0 (we add 1), and a finding can be marked
    `ignored`, which means a human already decided to accept it, so we skip it.
    """
    findings = []
    for item in data or []:
        if item.get("ignored"):
            continue
        locations = item.get("locations") or []
        # Prefer the location marked primary; otherwise the first one.
        primary = next((loc for loc in locations
                        if (loc.get("symbolic") or {}).get("kind") == "Primary"),
                       locations[0] if locations else {})
        symbolic = primary.get("symbolic") or {}
        local = (symbolic.get("key") or {}).get("Local") or {}
        path = local.get("verbatim_path") or local.get("given_path") or "?"
        start = ((primary.get("concrete") or {}).get("location") or {}).get("start_point") or {}
        row = start.get("row")
        ident = item.get("ident", "unknown")
        severity = (item.get("determinations") or {}).get("severity", "")
        url = item.get("url", "")
        findings.append(
            Finding(
                tool="zizmor",
                category="config",
                rule_id=ident,
                severity=_ZIZMOR_SEVERITY.get(str(severity).lower(), "info"),
                title=item.get("desc") or ident.replace("-", " "),
                file=_clean_path(path, root),
                line=row + 1 if isinstance(row, int) else None,
                description=symbolic.get("annotation", ""),
                fix=f"Explanation and remedy: {url}" if url else "",
            )
        )
    return findings


_ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _plain(text: str) -> str:
    """ZAP writes its descriptions as little HTML snippets. Reports are plain text, so we
    strip the tags (we never pass HTML through to the dashboard or the reports)."""
    import re
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(text or ""))).strip()


def parse_zap(data: Any, root: str = ".") -> list[Finding]:
    """OWASP ZAP tests a RUNNING web application, from the outside, like an attacker's
    browser would. Its traditional JSON report is: {"site": [{"@name": url, "alerts": [...]}]}
    where each alert has a name, a numeric `riskcode` (0 info, 1 low, 2 medium, 3 high),
    a description, a solution and a list of `instances` (the URLs where it was seen).

    We make ONE finding per alert, located at its first URL, and say how many URLs
    were affected. Findings belong to the "runtime" layer; they have no repository file,
    so `file` holds the URL instead.
    """
    sites = (data or {}).get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    findings = []
    for site in sites:
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or []
            first = instances[0].get("uri", "") if instances else ""
            where = first or site.get("@name", "") or "unknown URL"
            try:
                count = int(alert.get("count") or len(instances) or 1)
            except (TypeError, ValueError):
                count = len(instances) or 1
            rule = str(alert.get("alertRef") or alert.get("pluginid") or "zap")
            title = _plain(alert.get("name") or alert.get("alert") or rule)
            extra = f" Seen on {count} URL(s)." if count > 1 else ""
            findings.append(
                Finding(
                    tool="zap",
                    category="runtime",
                    rule_id=rule,
                    severity=_ZAP_RISK.get(str(alert.get("riskcode", "")), "info"),
                    title=title,
                    file=where,
                    package="",
                    description=(_plain(alert.get("desc")) + extra).strip(),
                    fix=_plain(alert.get("solution")),
                )
            )
    return findings


# One lookup table, so the runner never needs an if/else chain per tool.
ADAPTERS = {
    "gitleaks": parse_gitleaks,
    "semgrep": parse_semgrep,
    "trivy": parse_trivy,
    "zizmor": parse_zizmor,
    "zap": parse_zap,
}
