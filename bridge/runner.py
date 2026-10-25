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
            raw = ""
            if os.path.exists(report_path):
                with open(report_path) as handle:
                    raw = handle.read()
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
    detail = f"{len(findings)} finding(s)"

    # LESSON 16: never trust a scanner that says "0 findings" until you have seen it
    # find something. See gitleaks_self_test below.
    if tool == "gitleaks":
        passed, why = gitleaks_self_test()
        if passed:
            detail += "; self-test passed"
        else:
            return ToolRun(tool, "failed",
                           f"self-test FAILED, so its result cannot be trusted ({why}). "
                           f"It reported {len(findings)} finding(s).", findings)
    return ToolRun(tool, "ok", detail, findings)


# A made-up token that is NOT in the sample app. It is written in two pieces so that
# scanning this very file does not report it. It looks random on purpose, because
# scanners ignore strings that look obviously fake or patterned.
_CANARY_TOKEN = "ghp_" + "Zq8WmP3xK7vN2rT5yB9cH4jL6sD1fG0aXeUo"


def gitleaks_self_test() -> tuple[bool, str]:
    """LESSON 16 (the canary): plant a known fake secret in a temporary folder and make
    sure Gitleaks finds it, using the exact same command as the real scan.

    A scanner that silently finds nothing looks identical to a clean project, which is
    the most dangerous kind of failure. Real teams keep a "canary" like this and sound
    an alarm when it goes quiet. Returns (passed, reason if not).
    """
    with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as out:
        with open(os.path.join(source, "canary.py"), "w") as handle:
            handle.write(f'API_TOKEN = "{_CANARY_TOKEN}"\n')
        report_path = os.path.join(out, "canary-report.json")
        try:
            proc = subprocess.run(_command("gitleaks", report_path), cwd=source,
                                  capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return False, "the self-test timed out"
        if proc.returncode not in (0, 1):
            return False, f"the self-test command failed with exit code {proc.returncode}: " \
                          f"{proc.stderr.strip()[:200]}"
        try:
            with open(report_path) as handle:
                items = json.load(handle) or []
        except (OSError, json.JSONDecodeError):
            return False, "the self-test produced no readable report"
        if any(os.path.basename(str(item.get("File", ""))) == "canary.py" for item in items):
            return True, ""
        return False, "a planted fake token was not found"


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
