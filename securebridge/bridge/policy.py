"""The policy: the rules that decide whether the pipeline may continue.

LESSON 7 (policy as data): the rules live in policy.json, not in the code. A
security person can change "block at high" to "block at critical" without touching
Python. Big companies do the same thing with tools like OPA, where rules are
written in their own language and reviewed like code. Phase 2b adds
policy/securebridge.rego, which applies the same rules in OPA. policy.json stays
the settings file; the Rego mirrors the logic and runs in "shadow mode" (its
answer is compared with this file's, never enforced) until the two always agree.

LESSON 8 (waivers with an expiry date): real teams cannot fix everything today.
A waiver says "we know about this, here is why it is OK for now, and we will look
again on this date". Waivers that never expire become permanent holes, so every
waiver MUST have an expiry date, and expired waivers stop working automatically.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from .models import Finding, severity_rank


@dataclass
class Decision:
    blocked: bool
    blocking: list[Finding] = field(default_factory=list)
    waived: list[tuple] = field(default_factory=list)  # (Finding, waiver dict)
    expired_waivers: list[dict] = field(default_factory=list)


def load_policy(path: str) -> dict:
    with open(path) as handle:
        return json.load(handle)


def _waiver_for(finding: Finding, waivers: list[dict], today: date) -> tuple:
    """Return (matching active waiver or None, list of expired matches)."""
    expired = []
    for waiver in waivers:
        if waiver.get("rule_id") != finding.rule_id:
            continue
        if waiver.get("file") not in (None, finding.file):
            continue
        if date.fromisoformat(waiver["expires"]) < today:
            expired.append(waiver)
            continue
        return waiver, expired
    return None, expired


def evaluate(findings: list[Finding], policy: dict, today: Optional[date] = None) -> Decision:
    today = today or date.today()
    thresholds = policy.get("block_at", {})
    waivers = policy.get("waivers", [])
    decision = Decision(blocked=False)

    for finding in findings:
        # Which severity makes this kind of finding a blocker? "never" = never.
        limit = thresholds.get(finding.category, thresholds.get("default", "high"))
        if limit == "never" or severity_rank(finding.severity) < severity_rank(limit):
            continue

        waiver, expired = _waiver_for(finding, waivers, today)
        for old in expired:
            if old not in decision.expired_waivers:
                decision.expired_waivers.append(old)
        if waiver:
            decision.waived.append((finding, waiver))
        else:
            decision.blocking.append(finding)

    decision.blocked = bool(decision.blocking)
    return decision
