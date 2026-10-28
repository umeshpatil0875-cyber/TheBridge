"""Groups findings that point at the same thing to fix, WITHOUT deleting any of them.

LESSON 27 (findings are not problems): one flaw usually produces several findings. Three
Semgrep rules fire on the same line of code; five CVEs all say "upgrade flask". A team
that sees "24 blocking findings" feels buried, while the real work is maybe 12 fixes.
Grouping answers "how many things do I actually have to touch?".

The rule is deliberately simple and honest:
  - dependency findings group by PACKAGE: you fix them all by upgrading that one library
  - everything else groups by FILE AND LINE: several rules on the same line of code
    are usually one edit

This is DISPLAY ONLY. Every finding is still stored, counted, and used by the policy
exactly as before. (Lesson 15 warned that merging findings before the policy sees them
can hide a real one, so we never do that.)

Known limit: two tools can describe the same flaw at different places (Trivy flags
"Dockerfile" as a whole, Semgrep flags "Dockerfile:6"). Linking those needs a
hand-maintained mapping of rules, which commercial ASPM products maintain. We don't.
"""
from __future__ import annotations

import hashlib

SEVERITIES = ["info", "low", "medium", "high", "critical"]
LAYER_ORDER = ["source", "dependencies", "pipeline", "container", "infrastructure",
               "kubernetes", "runtime"]


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


def _layer_rank(layer: str) -> int:
    return LAYER_ORDER.index(layer) if layer in LAYER_ORDER else len(LAYER_ORDER)


def group_key(finding: dict) -> tuple:
    if finding.get("category") == "dependency" and finding.get("package"):
        return ("package", finding["package"], finding.get("file", ""))
    return ("location", finding.get("file", ""), finding.get("line") or 0)


def group_findings(findings: list[dict]) -> list[dict]:
    buckets: dict[tuple, list[dict]] = {}
    for finding in findings:
        buckets.setdefault(group_key(finding), []).append(finding)

    groups = []
    for key, items in buckets.items():
        items = sorted(items, key=lambda f: -_rank(f.get("severity", "")))
        worst = items[0]
        if key[0] == "package":
            where = f"{key[1]} ({key[2]})" if key[2] else key[1]
            kind = "package"
        else:
            where = key[1] + (f":{key[2]}" if key[2] else "")
            kind = "location"
        titles = []
        for f in items:
            if f["title"] not in titles:
                titles.append(f["title"])
        groups.append({
            "id": hashlib.sha256(repr(key).encode()).hexdigest()[:10],
            "kind": kind,
            "where": where,
            "layer": worst.get("layer", ""),
            "worst_severity": worst.get("severity", ""),
            "count": len(items),
            "tools": sorted({f["tool"] for f in items}),
            "rules": [f["rule_id"] for f in items],
            "titles": titles,
            "fix": ("Upgrade this library; the newest fix hint is in the list of findings."
                    if kind == "package" else worst.get("fix", "")),
        })
    groups.sort(key=lambda g: (-_rank(g["worst_severity"]), _layer_rank(g["layer"]),
                               -g["count"], g["where"]))
    return groups
