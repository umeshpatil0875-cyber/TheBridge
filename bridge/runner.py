"""Runs the scanners (or loads sample outputs) and returns normalized findings.

LESSON 6 (fail soft, say so loudly): a scanner might not be installed, might crash,
or might print something unexpected. The bridge must never crash because of one
tool, and it must NEVER silently pretend a skipped scan was clean. Every tool gets
a status (ok / skipped / failed / demo) that ends up in the report.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from .adapters import ADAPTERS
from .models import Finding, severity_rank

TIMEOUT_SECONDS = 600


@dataclass
class ToolRun:
    name: str
    status: str  # ok / skipped / failed / demo
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)


def _command(tool: str, report_path: str) -> list[str]:
    """The exact command line for each scanner. Every tool is told to scan the
    current folder (".") and to answer in JSON, because JSON is easy to parse."""
    if tool == "gitleaks":
        # --no-git: scan files as they are, ignore git history.
        # --exit-code 0: "found leaks" is not an error for the tool itself.
        return ["gitleaks", "detect", "--source", ".", "--no-git",
                "--report-format", "json", "--report-path", report_path,
                "--exit-code", "0"]
    if tool == "semgrep":
        return ["semgrep", "scan", "--config", "auto", "--json", "--quiet", "."]
    if tool == "trivy":
        # Secrets are left to Gitleaks, so the same leak is not reported twice.
        return ["trivy", "fs", "--format", "json", "--quiet",
                "--scanners", "vuln,misconfig", "."]
    raise ValueError(tool)


def run_real(tool: str, root: str) -> ToolRun:
    if shutil.which(tool) is None:
        return ToolRun(tool, "skipped", f"'{tool}' is not installed on this machine")

    with tempfile.TemporaryDirectory() as tmp:
        report_path = os.path.join(tmp, "gitleaks.json")
        try:
            proc = subprocess.run(
                _command(tool, report_path),
                cwd=root,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return ToolRun(tool, "failed", f"timed out after {TIMEOUT_SECONDS}s")

        # Gitleaks writes to a file; the others print to the screen (stdout).
        if tool == "gitleaks":
            raw = open(report_path).read() if os.path.exists(report_path) else ""
        else:
            raw = proc.stdout

        try:
            data = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            return ToolRun(tool, "failed",
                           f"output was not JSON. stderr: {proc.stderr.strip()[:200]}")

        if proc.returncode not in (0, 1):
            return ToolRun(tool, "failed",
                           f"exit code {proc.returncode}. stderr: {proc.stderr.strip()[:200]}")

    findings = ADAPTERS[tool](data, root)
    return ToolRun(tool, "ok", f"{len(findings)} finding(s)", findings)


def run_demo(tool: str, fixtures_dir: str, root: str) -> ToolRun:
    """Demo mode: read a saved sample output instead of running the real tool."""
    path = os.path.join(fixtures_dir, f"{tool}.json")
    with open(path) as handle:
        data = json.load(handle)
    findings = ADAPTERS[tool](data, root)
    return ToolRun(tool, "demo", f"{len(findings)} finding(s) from sample output", findings)


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Keep one finding per problem. If two tools report the same issue, keep the
    more severe one. Returns (unique findings, how many duplicates were dropped)."""
    best: dict[tuple, Finding] = {}
    dropped = 0
    for finding in findings:
        key = finding.dedupe_key
        if key in best:
            dropped += 1
            if severity_rank(finding.severity) > severity_rank(best[key].severity):
                best[key] = finding
        else:
            best[key] = finding
    return list(best.values()), dropped
