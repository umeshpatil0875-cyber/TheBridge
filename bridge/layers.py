"""The layer model: the DevOps stack, from the developer's keyboard to production.

LESSON 12 (layers): software does not go straight from a developer to users. It passes
through a chain of layers, and each layer can break in its own way:

  1. Source code     what developers write (and secrets accidentally left in it)
  2. Dependencies    third-party libraries the code pulls in
  3. CI/CD pipeline  the automatic assembly line that builds and ships the code
  4. Container image the packaged app (Docker)
  5. Infrastructure  servers, networks and cloud resources described as code (Terraform)
  6. Kubernetes      the system that runs many containers
  7. Running system  the live application in production

When something is wrong, the first question is "which layer?", because each layer
has a different owner and a different fix. The bridge now answers that question: every
finding is assigned to a layer, and the report lists the layers in order and marks
which ones are defective.

LESSON 13 (honest coverage): a layer with no findings is only "clean" if something
actually checked it. If no scanner looks at a layer, we say "not scanned" instead of
"clean". Showing a green tick for something nobody inspected is how breaches hide.
"""
from __future__ import annotations

import os
from typing import Optional

from .models import SEVERITIES, Finding, severity_rank

# The order here IS the order code travels. Index 0 is the earliest layer.
LAYERS = [
    ("source", "Source code"),
    ("dependencies", "Dependencies"),
    ("pipeline", "CI/CD pipeline"),
    ("container", "Container image"),
    ("infrastructure", "Infrastructure as code"),
    ("kubernetes", "Kubernetes"),
    ("runtime", "Running system"),
]
LAYER_NAMES = dict(LAYERS)

# Which of our scanners can see each layer today. An empty list means nothing in the
# bridge checks that layer yet. Adding a scanner later = adding its name here.
COVERAGE = {
    "source": ["gitleaks", "semgrep"],
    "dependencies": ["trivy"],
    "pipeline": [],  # needs a CI/CD-specific scanner, not included yet
    "container": ["trivy"],
    "infrastructure": ["trivy"],
    "kubernetes": ["trivy"],
    "runtime": [],  # needs tools that test a live system, not included yet
}


def _looks_like_kubernetes(path: str) -> bool:
    """A YAML file is a Kubernetes manifest if it declares apiVersion and kind."""
    try:
        with open(path, errors="ignore") as handle:
            text = handle.read(20000)
    except OSError:
        return False
    return "apiVersion:" in text and "kind:" in text


def classify(finding: Finding, root: str = ".") -> str:
    """Decide which layer a finding belongs to. Rules are simple and visible on purpose."""
    if finding.category == "dependency":
        return "dependencies"
    if finding.category == "secret":
        return "source"  # a leaked credential is a source-code problem wherever it sits

    # Code and configuration findings: the FILE tells us which layer it is about.
    # This matters because one tool can report on several layers. A real run showed
    # Semgrep flagging the Dockerfile and a Kubernetes file, and filing those under
    # "Source code" was wrong. Looking at the file name first avoids that.
    path = finding.file.replace("\\", "/")
    lower = path.lower()
    base = os.path.basename(lower)

    if base.startswith("dockerfile") or base.endswith(".dockerfile") or base == "containerfile":
        return "container"
    if lower.endswith((".tf", ".tf.json", ".tfvars")):
        return "infrastructure"
    if ".github/workflows/" in lower or base in (".gitlab-ci.yml", "jenkinsfile"):
        return "pipeline"
    if lower.endswith((".yaml", ".yml")):
        full = os.path.realpath(os.path.join(root, path))
        # Only read files that are really inside the scanned folder.
        if full.startswith(os.path.realpath(root) + os.sep) and _looks_like_kubernetes(full):
            return "kubernetes"
    return "source"


def summarize(runs, findings: list[Finding], decision) -> list[dict]:
    """One row per layer, in stack order, saying how healthy it is."""
    ran = {r.name for r in runs if r.status in ("ok", "demo")}
    blocking_ids = {id(f) for f in decision.blocking}
    rows = []
    for key, name in LAYERS:
        here = [f for f in findings if f.layer == key]
        blocking = [f for f in here if id(f) in blocking_ids]
        checkers = COVERAGE[key]
        active = [t for t in checkers if t in ran]

        if blocking:
            status = "DEFECTIVE"
        elif here:
            status = "warnings only"
        elif active:
            status = "clean"
        else:
            status = "not scanned"

        worst: Optional[str] = None
        if here:
            worst = max((f.severity for f in here), key=severity_rank)
        rows.append(
            {
                "layer": key,
                "name": name,
                "status": status,
                "findings": len(here),
                "blocking": len(blocking),
                "worst_severity": worst,
                "checked_by": active,
                "gap": "" if active else (
                    "no scanner for this layer yet" if not checkers
                    else "its scanner did not run"),
            }
        )
    return rows


def first_defective(rows: list[dict]) -> Optional[dict]:
    """The earliest broken layer. Problems upstream tend to cause problems downstream
    (a vulnerable library ends up inside the container), so start fixing here."""
    for row in rows:
        if row["status"] == "DEFECTIVE":
            return row
    return None
