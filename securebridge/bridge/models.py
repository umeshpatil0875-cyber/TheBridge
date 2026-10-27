"""The ONE common shape every scanner result is converted into.

LESSON 1 (see LESSONS.md): every scanner speaks its own language. Gitleaks calls
the file "File", Semgrep calls it "path", Trivy calls it "Target". Before we can
compare, rank or block anything, we translate all of them into this single shape.
Everything else in the project (policy, reports, dashboard later) only ever sees
`Finding`, never a tool's raw output. That is what makes the bridge easy to extend:
supporting a new scanner means writing one small translator, nothing else changes.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

# Ordered from least to most serious. The position in this list IS the rank.
SEVERITIES = ["info", "low", "medium", "high", "critical"]

# What kind of problem is it? The policy can treat each kind differently.
CATEGORIES = ["secret", "code", "dependency", "config"]


def severity_rank(severity: str) -> int:
    """Turn a severity word into a number so we can compare them."""
    return SEVERITIES.index(severity)


@dataclass
class Finding:
    tool: str  # which scanner found it: gitleaks / semgrep / trivy
    category: str  # secret / code / dependency / config
    rule_id: str  # the scanner's own id for the check, e.g. CVE-2018-18074
    severity: str  # one of SEVERITIES
    title: str  # short human sentence
    file: str  # path relative to the scanned folder
    line: Optional[int] = None  # line number, if the tool knows it
    package: str = ""  # for dependency findings: the library name
    description: str = ""  # longer explanation
    fix: str = ""  # what to do about it
    layer: str = ""  # which DevOps layer it belongs to (set by layers.classify)

    @property
    def dedupe_key(self) -> tuple:
        """Two findings with the same key are the same problem seen twice.

        LESSON 4: when several tools are connected, they can report the same issue
        (two tools both spot the same leaked password). Without dedupe the team sees
        the problem twice and loses trust in the report.

        LESSON 15 (learned from a real run): merging too eagerly is WORSE than not
        merging. The first version keyed everything on file + line, so two different
        rules firing on the same line looked like "the same problem", and one of them,
        a privileged container, silently vanished from the report. Now only findings
        that are provably the same are merged:
          - a secret at the same place, even if two tools found it
          - the same CVE in the same package, even if two tools found it
          - anything else only when it is the same rule from the same tool at the
            same place (an exact repeat)
        Linking DIFFERENT rules or tools that describe one underlying issue needs a
        hand-made mapping table; commercial ASPM products maintain exactly that.
        """
        if self.category == "secret":
            return ("secret", self.file, self.line)
        if self.category == "dependency":
            return ("dependency", self.package, self.rule_id)
        return (self.category, self.tool, self.rule_id, self.file, self.line)

    def to_dict(self) -> dict:
        return asdict(self)
