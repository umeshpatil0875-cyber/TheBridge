"""The database: where every scan is kept, so we can see history instead of one report.

LESSON 21 (why a database): until now every run produced a report and forgot it. A team
needs to ask questions over time: "is it getting better?", "what is NEW since last
week?", "when did this finding first appear?". That needs memory, so each scan is saved.

We use SQLite (a database that is just one file, built into Python) so there is nothing
to install. The shape is the same as a hosted database like PostgreSQL: the SQL and the
tables would barely change when this becomes a real service.

LESSON 22 (multi-tenancy): a SaaS serves many customers from one database. Every scan
belongs to a PROJECT, and every query below filters by project_id. Forgetting that one
filter is how real SaaS products leak one customer's data to another, so the filter is
built into the functions and a test checks that projects cannot see each other.

LESSON 23 (never store secrets you can avoid storing): project API tokens are shown
once, and only a SHA-256 hash is saved. If the database file leaks, the attacker gets
hashes, not working tokens.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .grouping import group_findings
from .models import SEVERITIES, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id            INTEGER NOT NULL REFERENCES projects(id),
    created_at            TEXT NOT NULL,
    commit_sha            TEXT NOT NULL DEFAULT '',
    branch                TEXT NOT NULL DEFAULT '',
    verdict               TEXT NOT NULL,
    blocking_count        INTEGER NOT NULL,
    first_defective_layer TEXT,
    report_json           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    fingerprint TEXT NOT NULL,
    tool TEXT, category TEXT, rule_id TEXT, severity TEXT, title TEXT,
    file TEXT, line INTEGER, package TEXT, layer TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id, id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""

REQUIRED_FINDING_FIELDS = ("tool", "category", "rule_id", "severity", "title", "file")


class ValidationError(ValueError):
    """The uploaded report is not something we are willing to store."""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_project(conn: sqlite3.Connection, name: str) -> str:
    """Returns the API token. This is the only time the real token exists."""
    name = name.strip()
    if not name:
        raise ValidationError("project name is empty")
    token = "sb_" + secrets.token_urlsafe(32)
    try:
        conn.execute("INSERT INTO projects (name, token_hash, created_at) VALUES (?, ?, ?)",
                     (name, _hash(token), _now()))
    except sqlite3.IntegrityError:
        raise ValidationError(f"a project named '{name}' already exists") from None
    conn.commit()
    return token


def authenticate(conn: sqlite3.Connection, token: str) -> Optional[int]:
    """Project id for a valid token, else None."""
    if not token:
        return None
    row = conn.execute("SELECT id FROM projects WHERE token_hash = ?", (_hash(token),)).fetchone()
    return row["id"] if row else None


def validate_report(report) -> list[dict]:
    """Check an uploaded report.json and return its findings. Reject anything odd,
    because stored data is trusted by every later query and chart."""
    if not isinstance(report, dict):
        raise ValidationError("report must be a JSON object")
    if report.get("verdict") not in ("passed", "blocked"):
        raise ValidationError("report.verdict must be 'passed' or 'blocked'")
    if not isinstance(report.get("blocking_count"), int) or report["blocking_count"] < 0:
        raise ValidationError("report.blocking_count must be a non-negative integer")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValidationError("report.findings must be a list")
    for number, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValidationError(f"finding {number} is not an object")
        for key in REQUIRED_FINDING_FIELDS:
            if not isinstance(item.get(key), str) or not item[key]:
                raise ValidationError(f"finding {number} is missing '{key}'")
        if item["severity"] not in SEVERITIES:
            raise ValidationError(f"finding {number} has unknown severity '{item['severity']}'")
    return findings


def _fingerprint(item: dict) -> str:
    """The identity of a problem across scans: the same one found again next week has
    the same fingerprint, so we can tell NEW from OLD. Reuses the dedupe key."""
    finding = Finding(**{k: item.get(k, d) for k, d in
                         (("tool", ""), ("category", ""), ("rule_id", ""), ("severity", ""),
                          ("title", ""), ("file", ""), ("line", None), ("package", ""))})
    return hashlib.sha256(json.dumps(finding.dedupe_key, default=str).encode()).hexdigest()[:16]


def save_scan(conn: sqlite3.Connection, project_id: int, report: dict,
              commit: str = "", branch: str = "") -> dict:
    findings = validate_report(report)
    previous = conn.execute("SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 1",
                            (project_id,)).fetchone()
    before = set()
    if previous:
        before = {r["fingerprint"] for r in conn.execute(
            "SELECT fingerprint FROM findings WHERE scan_id = ? AND project_id = ?",
            (previous["id"], project_id))}

    cur = conn.execute(
        "INSERT INTO scans (project_id, created_at, commit_sha, branch, verdict, blocking_count,"
        " first_defective_layer, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (project_id, _now(), str(commit)[:64], str(branch)[:200], report["verdict"],
         report["blocking_count"], report.get("first_defective_layer"), json.dumps(report)))
    scan_id = cur.lastrowid
    now = set()
    for item in findings:
        fp = _fingerprint(item)
        now.add(fp)
        conn.execute(
            "INSERT INTO findings (scan_id, project_id, fingerprint, tool, category, rule_id,"
            " severity, title, file, line, package, layer) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, project_id, fp, item["tool"], item["category"], item["rule_id"],
             item["severity"], item["title"], item["file"], item.get("line"),
             item.get("package", ""), item.get("layer", "")))
    conn.commit()
    return {"id": scan_id, "verdict": report["verdict"], "findings": len(findings),
            "new": len(now - before) if previous else None,
            "fixed": len(before - now) if previous else None}


def list_scans(conn: sqlite3.Connection, project_id: int, limit: int = 20) -> list[dict]:
    limit = max(1, min(int(limit), 200))
    rows = conn.execute(
        "SELECT s.id, s.created_at, s.commit_sha, s.branch, s.verdict, s.blocking_count,"
        " s.first_defective_layer, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS total"
        " FROM scans s WHERE s.project_id = ? ORDER BY s.id DESC LIMIT ?", (project_id, limit))
    return [dict(r) for r in rows]


def get_scan(conn: sqlite3.Connection, project_id: int, scan_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM scans WHERE id = ? AND project_id = ?",
                       (scan_id, project_id)).fetchone()
    if not row:
        return None
    scan = {k: row[k] for k in ("id", "created_at", "commit_sha", "branch", "verdict",
                                "blocking_count", "first_defective_layer")}
    scan["problems"] = []
    try:
        scan["problems"] = group_findings(json.loads(row["report_json"]).get("findings", []))
    except (ValueError, KeyError, TypeError):
        pass  # an unreadable old report just has no grouped view
    scan["findings"] = [dict(r) for r in conn.execute(
        "SELECT fingerprint, tool, category, rule_id, severity, title, file, line, package, layer"
        " FROM findings WHERE scan_id = ? AND project_id = ? ORDER BY id", (scan_id, project_id))]
    return scan


def trend(conn: sqlite3.Connection, project_id: int, limit: int = 30) -> list[dict]:
    """Oldest to newest, so it can be drawn left to right as a chart."""
    return list(reversed(list_scans(conn, project_id, limit)))


def insights(conn: sqlite3.Connection, project_id: int, limit: int = 30) -> list[dict]:
    """Everything the dashboard draws, one entry per scan, oldest first: counts by
    severity, layer, tool and category, plus how many findings are new / fixed compared
    with the scan before it. Always filtered by project_id (Lesson 22)."""
    scans = trend(conn, project_id, limit)
    if not scans:
        return []
    ids = [s["id"] for s in scans]
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT scan_id, severity, layer, tool, category, fingerprint FROM findings"
        f" WHERE project_id = ? AND scan_id IN ({marks})", [project_id, *ids]).fetchall()
    per: dict[int, dict] = {i: {"severity": {}, "layers": {}, "tools": {}, "categories": {},
                               "fingerprints": set()} for i in ids}
    for r in rows:
        bucket = per[r["scan_id"]]
        for key, value in (("severity", r["severity"]), ("layers", r["layer"]),
                           ("tools", r["tool"]), ("categories", r["category"])):
            bucket[key][value] = bucket[key].get(value, 0) + 1
        bucket["fingerprints"].add(r["fingerprint"])
    out, previous = [], None
    for scan in scans:
        bucket = per[scan["id"]]
        entry = dict(scan)
        entry.update({k: bucket[k] for k in ("severity", "layers", "tools", "categories")})
        now = bucket["fingerprints"]
        entry["new"] = len(now - previous) if previous is not None else None
        entry["fixed"] = len(previous - now) if previous is not None else None
        previous = now
        out.append(entry)
    return out
