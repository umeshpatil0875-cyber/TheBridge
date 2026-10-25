"""Turns findings and the policy decision into things people and tools can read.

Three outputs, three audiences:
  report.md    for humans (read it, paste it into a pull request)
  report.json  for programs (a dashboard or API in a later phase reads this)
  report.sarif for GitHub and other security viewers

LESSON 9 (SARIF): SARIF is an open standard format for scanner results. If we write
it once, GitHub's "Security" tab can show our findings with no extra work, because
GitHub already understands SARIF. This is why the bridge converts everything into
ONE format first, then exports ONE standard format at the end.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

from .models import SEVERITIES, Finding, severity_rank
from .policy import Decision
from .runner import ToolRun


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-severity_rank(f.severity), f.file, f.line or 0))


def _where(finding: Finding) -> str:
    return f"{finding.file}:{finding.line}" if finding.line else finding.file


def to_markdown(runs: list[ToolRun], findings: list[Finding], decision: Decision,
                dropped: int) -> str:
    counts = Counter(f.severity for f in findings)
    out = ["# SecureBridge report", ""]

    verdict = "BLOCKED" if decision.blocked else "PASSED"
    out += [f"**Verdict: {verdict}** "
            f"({len(decision.blocking)} blocking, {len(decision.waived)} waived)", ""]

    out += ["## Scanners", "", "| Scanner | Status | Detail |", "| --- | --- | --- |"]
    for run in runs:
        out.append(f"| {run.name} | {run.status} | {run.detail} |")
    skipped = [r.name for r in runs if r.status in ("skipped", "failed")]
    if skipped:
        out += ["", f"**Warning:** {', '.join(skipped)} did not run. "
                "This report does NOT cover what those scanners check."]

    out += ["", "## Findings by severity", "", "| Severity | Count |", "| --- | --- |"]
    for sev in reversed(SEVERITIES):
        if counts.get(sev):
            out.append(f"| {sev} | {counts[sev]} |")
    if not findings:
        out.append("| none | 0 |")
    if dropped:
        out += ["", f"{dropped} duplicate finding(s) from different tools were merged."]

    blocking_ids = {id(f) for f in decision.blocking}
    out += ["", "## All findings", "",
            "| Severity | Kind | Where | What | Fix | Blocks? |",
            "| --- | --- | --- | --- | --- | --- |"]
    for f in _sorted(findings):
        blocks = "yes" if id(f) in blocking_ids else "no"
        what = f"{f.title} ({f.rule_id})".replace("|", "/")
        out.append(f"| {f.severity} | {f.category} | {_where(f)} | {what} | "
                   f"{f.fix.replace('|', '/')} | {blocks} |")

    if decision.waived:
        out += ["", "## Waived (known and accepted)", ""]
        for f, w in decision.waived:
            out.append(f"- {f.rule_id} in {_where(f)}: {w['reason']} (expires {w['expires']})")
    if decision.expired_waivers:
        out += ["", "## Expired waivers (no longer protect anything)", ""]
        for w in decision.expired_waivers:
            out.append(f"- {w['rule_id']}: expired {w['expires']}")
    return "\n".join(out) + "\n"


def to_json(runs: list[ToolRun], findings: list[Finding], decision: Decision,
            dropped: int) -> str:
    return json.dumps(
        {
            "verdict": "blocked" if decision.blocked else "passed",
            "blocking_count": len(decision.blocking),
            "duplicates_merged": dropped,
            "scanners": [{"name": r.name, "status": r.status, "detail": r.detail} for r in runs],
            "findings": [f.to_dict() for f in _sorted(findings)],
        },
        indent=2,
    )


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(findings: list[Finding]) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in _sorted(findings):
        rule_id = f"{f.tool}/{f.rule_id}"
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": f.title}})
        location = {"artifactLocation": {"uri": f.file}}
        if f.line:
            location["region"] = {"startLine": f.line}
        fingerprint = hashlib.sha256(
            "|".join(str(part) for part in f.dedupe_key + (f.tool, f.rule_id)).encode()
        ).hexdigest()
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.description} Fix: {f.fix}".strip()},
                "locations": [{"physicalLocation": location}],
                "partialFingerprints": {"securebridge/v1": fingerprint},
                "properties": {"severity": f.severity, "category": f.category, "tool": f.tool},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SecureBridge", "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)
