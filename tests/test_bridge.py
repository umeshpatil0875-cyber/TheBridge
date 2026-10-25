"""Tests. Run them with:  python3 -m unittest discover -s tests -v

LESSON 11: tests are how you trust the bridge. A security tool that silently
gives wrong answers is worse than no tool, so the important behaviours are pinned
down here: severity mapping, dedupe, policy, waivers, and "secrets never leak".
"""
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from io import StringIO
from unittest import mock

from bridge import adapters, cli, report
from bridge.models import Finding
from bridge.policy import evaluate
from bridge.runner import deduplicate, run_demo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures")
APP = os.path.join(ROOT, "sample-app")
FAKE_TOKEN = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6"


def load(name):
    with open(os.path.join(FIXTURES, f"{name}.json")) as handle:
        return json.load(handle)


def all_demo_findings():
    return [f for tool in ("gitleaks", "semgrep", "trivy")
            for f in run_demo(tool, FIXTURES, APP).findings]


class AdapterTests(unittest.TestCase):
    def test_gitleaks_maps_to_secret_high_without_the_secret(self):
        (finding,) = adapters.parse_gitleaks(load("gitleaks"), APP)
        self.assertEqual((finding.category, finding.severity), ("secret", "high"))
        self.assertEqual((finding.file, finding.line), ("config.py", 5))
        self.assertNotIn(FAKE_TOKEN, json.dumps(finding.to_dict()))

    def test_gitleaks_empty_report_means_no_findings(self):
        self.assertEqual(adapters.parse_gitleaks(None), [])
        self.assertEqual(adapters.parse_gitleaks([]), [])

    def test_semgrep_severity_mapping(self):
        by_line = {f.line: f.severity for f in adapters.parse_semgrep(load("semgrep"), APP)}
        self.assertEqual(by_line, {20: "high", 28: "high", 33: "medium"})

    def test_trivy_splits_dependencies_and_config(self):
        findings = adapters.parse_trivy(load("trivy"), APP)
        kinds = [f.category for f in findings]
        self.assertEqual(kinds.count("dependency"), 6)
        self.assertEqual(kinds.count("config"), 1)
        pyyaml = [f for f in findings if f.package == "pyyaml"]
        self.assertTrue(all("Upgrade pyyaml" in f.fix for f in pyyaml))

    def test_absolute_paths_become_relative(self):
        data = [{"File": os.path.join(APP, "config.py"), "StartLine": 5, "RuleID": "x"}]
        self.assertEqual(adapters.parse_gitleaks(data, APP)[0].file, "config.py")


class FixtureHonestyTests(unittest.TestCase):
    def test_every_finding_points_at_a_real_file_and_line(self):
        """Sample outputs must match the sample app, or the demo would mislead."""
        for finding in all_demo_findings():
            path = os.path.join(APP, finding.file)
            self.assertTrue(os.path.exists(path), f"{finding.file} does not exist")
            if finding.line:
                with open(path) as handle:
                    self.assertLessEqual(finding.line, len(handle.readlines()))


class DedupeTests(unittest.TestCase):
    def test_same_secret_from_two_tools_is_merged_keeping_the_worse_severity(self):
        a = Finding("gitleaks", "secret", "github-pat", "high", "t", "config.py", 5)
        b = Finding("trivy", "secret", "github-token", "critical", "t", "config.py", 5)
        unique, dropped = deduplicate([a, b])
        self.assertEqual((len(unique), dropped), (1, 1))
        self.assertEqual(unique[0].severity, "critical")

    def test_different_cves_on_the_same_package_stay_separate(self):
        findings = adapters.parse_trivy(load("trivy"), APP)
        unique, dropped = deduplicate(findings)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(unique), len(findings))


POLICY = {
    "block_at": {"secret": "low", "code": "high", "dependency": "high", "config": "high"},
    "waivers": [],
}


class PolicyTests(unittest.TestCase):
    def test_medium_code_issue_does_not_block_but_high_does(self):
        medium = Finding("semgrep", "code", "r", "medium", "t", "a.py", 1)
        high = Finding("semgrep", "code", "r2", "high", "t", "a.py", 2)
        self.assertFalse(evaluate([medium], POLICY).blocked)
        self.assertTrue(evaluate([high], POLICY).blocked)

    def test_any_secret_blocks_even_at_low_severity(self):
        low_secret = Finding("gitleaks", "secret", "r", "low", "t", "a.py", 1)
        self.assertTrue(evaluate([low_secret], POLICY).blocked)

    def test_active_waiver_unblocks_and_is_listed(self):
        finding = Finding("trivy", "dependency", "CVE-1", "high", "t", "req.txt", package="p")
        policy = {**POLICY, "waivers": [
            {"rule_id": "CVE-1", "file": "req.txt", "reason": "ok", "expires": "2026-12-31"}]}
        decision = evaluate([finding], policy, today=date(2026, 10, 24))
        self.assertFalse(decision.blocked)
        self.assertEqual(len(decision.waived), 1)

    def test_expired_waiver_stops_protecting(self):
        finding = Finding("trivy", "dependency", "CVE-1", "high", "t", "req.txt", package="p")
        policy = {**POLICY, "waivers": [
            {"rule_id": "CVE-1", "file": "req.txt", "reason": "ok", "expires": "2026-12-31"}]}
        decision = evaluate([finding], policy, today=date(2027, 1, 1))
        self.assertTrue(decision.blocked)
        self.assertEqual(len(decision.expired_waivers), 1)


class ReportTests(unittest.TestCase):
    def test_sarif_has_the_required_shape(self):
        sarif = json.loads(report.to_sarif(all_demo_findings()))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SecureBridge")
        self.assertEqual(len(run["results"]), 11)
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)
            self.assertIn(result["level"], {"error", "warning", "note"})
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri)


class EndToEndTests(unittest.TestCase):
    def run_cli(self, argv):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = cli.main(argv)
        return code, buffer.getvalue()

    def test_demo_scan_is_blocked_writes_reports_and_never_leaks_the_secret(self):
        with tempfile.TemporaryDirectory() as out:
            code, _ = self.run_cli(["scan", APP, "--demo", "--out", out])
            self.assertEqual(code, 1)
            for name in ("report.md", "report.json", "report.sarif"):
                path = os.path.join(out, name)
                self.assertTrue(os.path.exists(path), name)
                with open(path) as handle:
                    self.assertNotIn(FAKE_TOKEN, handle.read(), f"secret leaked into {name}")

    def test_with_no_tools_installed_it_refuses_instead_of_claiming_clean(self):
        with tempfile.TemporaryDirectory() as out, mock.patch("shutil.which", return_value=None):
            code, _ = self.run_cli(["scan", APP, "--out", out])
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(os.path.join(out, "report.md")))

    def test_a_clean_folder_passes(self):
        with tempfile.TemporaryDirectory() as out, \
                mock.patch("bridge.cli.run_demo") as fake:
            from bridge.runner import ToolRun
            fake.side_effect = lambda tool, *_: ToolRun(tool, "demo", "0 finding(s)")
            code, text = self.run_cli(["scan", APP, "--demo", "--out", out])
            self.assertEqual(code, 0)
            self.assertIn("PASSED", text)


if __name__ == "__main__":
    unittest.main()
