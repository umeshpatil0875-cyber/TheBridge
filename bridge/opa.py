"""Asks OPA (Open Policy Agent) the same question the Python policy answers.

LESSON 19 (shadow mode): changing how your security decisions are made is risky. If the
new engine is wrong in one direction, real problems slip through; in the other, every
pull request is blocked for no reason. So teams do not switch over in one step. They run
the new engine in SHADOW MODE first: the old engine still decides, the new one evaluates
the exact same input, and any disagreement is shown to humans. Only after the two agree
on real data for a while does the new engine take over.

This module is the "ask OPA and compare" half of that. The decision logic itself lives in
policy/securebridge.rego, written in Rego.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import date
from typing import Optional

from .models import Finding
from .policy import Decision

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGO = os.path.join(HERE, "policy", "securebridge.rego")
TIMEOUT_SECONDS = 60


@dataclass
class OpaResult:
    status: str  # ok / skipped / error
    detail: str = ""
    decision: Optional[dict] = None


def build_input(findings: list[Finding], policy: dict, today: Optional[date] = None) -> dict:
    """The document OPA receives. `policy` is the same policy.json the Python engine
    reads, so there is exactly one place where thresholds and waivers are edited."""
    return {
        "findings": [f.to_dict() for f in findings],
        "policy": policy,
        "today": (today or date.today()).isoformat(),
    }


def ask_opa(opa_input: dict, rego_path: str = DEFAULT_REGO) -> OpaResult:
    if shutil.which("opa") is None:
        return OpaResult("skipped", "'opa' is not installed on this machine")
    if not os.path.exists(rego_path):
        return OpaResult("error", f"policy file not found: {rego_path}")

    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w") as handle:
            json.dump(opa_input, handle)
        try:
            proc = subprocess.run(
                ["opa", "eval", "--format", "json", "--data", rego_path,
                 "--input", input_path, "data.securebridge.decision"],
                capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return OpaResult("error", f"opa timed out after {TIMEOUT_SECONDS}s")

    if proc.returncode != 0:
        message = (proc.stderr.strip() or proc.stdout.strip())[:300]
        return OpaResult("error", f"opa exited with code {proc.returncode}: {message}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return OpaResult("error", f"opa output was not JSON: {proc.stdout.strip()[:200]}")

    # OPA answers {"result": [{"expressions": [{"value": ...}]}]}. If the policy's answer
    # is "undefined" the "result" key is missing entirely. Undefined is NOT the same as
    # "pass", so we call it out as an error instead of treating it as a clean verdict.
    try:
        value = payload["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError):
        return OpaResult("error", "the policy returned no decision (undefined)")
    if not isinstance(value, dict) or "blocked" not in value:
        return OpaResult("error", f"unexpected decision shape: {str(value)[:200]}")
    return OpaResult("ok", "", value)


def shadow_check(findings: list[Finding], policy: dict, decision: Decision,
                 rego_path: str = DEFAULT_REGO, today: Optional[date] = None) -> dict:
    """Compare OPA's answer with the Python engine's. Never changes the real verdict."""
    python_side = {"blocked": decision.blocked, "blocking": len(decision.blocking),
                   "waived": len(decision.waived)}
    result = ask_opa(build_input(findings, policy, today), rego_path)
    check = {"engine": "opa", "mode": "shadow", "python": python_side,
             "opa": None, "status": result.status, "detail": result.detail}
    if result.status != "ok":
        return check

    opa_side = {key: result.decision.get(key) for key in ("blocked", "blocking", "waived")}
    check["opa"] = opa_side
    differences = [f"{key}: python={python_side[key]} opa={opa_side[key]}"
                   for key in python_side if python_side[key] != opa_side[key]]
    if result.decision.get("invalid"):
        differences.append(f"opa saw {result.decision['invalid']} finding(s) with an "
                           "unknown severity")
    check["status"] = "disagree" if differences else "agree"
    check["detail"] = "; ".join(differences)
    return check
