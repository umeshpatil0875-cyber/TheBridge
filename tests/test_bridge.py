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

from bridge import adapters, cli, layers, report
from bridge.models import Finding
from bridge.policy import evaluate
from bridge.runner import ToolRun, deduplicate, run_demo

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
        self.assertEqual(kinds.count("config"), 3)
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

    def test_two_different_rules_on_the_same_line_are_both_kept(self):
        """Regression from a real run: the privileged-container finding (KSV-0017) was
        merged away because another rule (KSV-0014) fired on the same file and line."""
        a = Finding("trivy", "config", "KSV-0014", "high", "read-only fs", "k8s/deployment.yaml", 16)
        b = Finding("trivy", "config", "KSV-0017", "high", "privileged", "k8s/deployment.yaml", 16)
        unique, dropped = deduplicate([a, b])
        self.assertEqual((len(unique), dropped), (2, 0))

    def test_findings_without_a_line_number_in_one_file_stay_separate(self):
        a = Finding("trivy", "config", "DS-0002", "high", "root user", "Dockerfile")
        b = Finding("trivy", "config", "DS-0026", "low", "no healthcheck", "Dockerfile")
        unique, dropped = deduplicate([a, b])
        self.assertEqual((len(unique), dropped), (2, 0))

    def test_an_exact_repeat_is_still_merged(self):
        a = Finding("semgrep", "code", "rule-x", "high", "t", "app.py", 20)
        b = Finding("semgrep", "code", "rule-x", "high", "t", "app.py", 20)
        unique, dropped = deduplicate([a, b])
        self.assertEqual((len(unique), dropped), (1, 1))

    def test_same_cve_in_the_same_package_from_two_tools_is_merged(self):
        a = Finding("trivy", "dependency", "CVE-1", "high", "t", "requirements.txt", package="flask")
        b = Finding("other", "dependency", "CVE-1", "critical", "t", "requirements.txt", package="flask")
        unique, dropped = deduplicate([a, b])
        self.assertEqual((len(unique), dropped, unique[0].severity), (1, 1, "critical"))

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
        self.assertEqual(len(run["results"]), 13)
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)
            self.assertIn(result["level"], {"error", "warning", "note"})
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri)


class LayerTests(unittest.TestCase):
    def finding(self, category, file, **kw):
        return Finding("t", category, "r", kw.get("severity", "high"), "t", file, 1)

    def test_each_kind_of_finding_lands_in_the_right_layer(self):
        cases = [
            (self.finding("secret", "config.py"), "source"),
            (self.finding("code", "app.py"), "source"),
            (self.finding("dependency", "requirements.txt"), "dependencies"),
            (self.finding("config", "Dockerfile"), "container"),
            (self.finding("config", "infra/main.tf"), "infrastructure"),
            (self.finding("config", "k8s/deployment.yaml"), "kubernetes"),
            (self.finding("config", ".github/workflows/ci.yml"), "pipeline"),
        ]
        for finding, expected in cases:
            self.assertEqual(layers.classify(finding, APP), expected, finding.file)

    def test_code_findings_in_non_source_files_go_to_the_layer_of_that_file(self):
        """Regression from a real run: Semgrep findings in the Dockerfile and a
        Kubernetes manifest were being filed under Source code."""
        cases = [
            (self.finding("code", "Dockerfile"), "container"),
            (self.finding("code", "k8s/deployment.yaml"), "kubernetes"),
            (self.finding("code", "infra/main.tf"), "infrastructure"),
            (self.finding("code", ".github/workflows/ci.yml"), "pipeline"),
            (self.finding("code", "app.py"), "source"),
            (self.finding("secret", "Dockerfile"), "source"),
        ]
        for finding, expected in cases:
            self.assertEqual(layers.classify(finding, APP), expected, finding.file)

    def test_plain_yaml_that_is_not_kubernetes_is_not_labelled_kubernetes(self):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, "settings.yaml"), "w") as handle:
                handle.write("colour: blue\n")
            finding = self.finding("config", "settings.yaml")
            self.assertNotEqual(layers.classify(finding, folder), "kubernetes")

    def test_path_tricks_cannot_make_the_classifier_read_outside_the_folder(self):
        finding = self.finding("config", "../../etc/passwd.yaml")
        self.assertNotEqual(layers.classify(finding, APP), "kubernetes")

    def classified(self):
        runs = [run_demo(t, FIXTURES, APP) for t in ("gitleaks", "semgrep", "trivy")]
        findings, _ = deduplicate([f for r in runs for f in r.findings])
        for f in findings:
            f.layer = layers.classify(f, APP)
        return runs, findings, evaluate(findings, load_policy_file())

    def test_summary_marks_defective_clean_and_unscanned_layers_honestly(self):
        runs, findings, decision = self.classified()
        status = {r["layer"]: r["status"] for r in layers.summarize(runs, findings, decision)}
        for broken in ("source", "dependencies", "container", "infrastructure", "kubernetes"):
            self.assertEqual(status[broken], "DEFECTIVE", broken)
        # Nothing in the bridge checks these, so "clean" would be a lie.
        self.assertEqual(status["pipeline"], "not scanned")
        self.assertEqual(status["runtime"], "not scanned")

    def test_first_defective_layer_is_the_earliest_one(self):
        runs, findings, decision = self.classified()
        rows = layers.summarize(runs, findings, decision)
        self.assertEqual(layers.first_defective(rows)["layer"], "source")

    def test_a_scanned_layer_with_no_findings_is_clean_but_only_if_its_scanner_ran(self):
        runs, _, decision = self.classified()
        ran = layers.summarize(runs, [], evaluate([], POLICY))
        self.assertEqual({r["layer"]: r["status"] for r in ran}["container"], "clean")
        skipped = [ToolRun("trivy", "skipped", "not installed")]
        rows = layers.summarize(skipped, [], evaluate([], POLICY))
        self.assertEqual({r["layer"]: r["status"] for r in rows}["container"], "not scanned")

    def test_json_report_names_the_first_defective_layer(self):
        runs, findings, decision = self.classified()
        data = json.loads(report.to_json(runs, findings, decision, 0))
        self.assertEqual(data["first_defective_layer"], "source")
        self.assertEqual([l["layer"] for l in data["layers"]], [k for k, _ in layers.LAYERS])


def load_policy_file():
    from bridge.policy import load_policy
    return load_policy(os.path.join(ROOT, "policy.json"))


class SarifPathTests(unittest.TestCase):
    def test_prefix_makes_paths_relative_to_the_repo_root(self):
        finding = Finding("t", "code", "r", "high", "t", "config.py", 5)
        uri = lambda text: json.loads(text)["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri(report.to_sarif([finding])), "config.py")
        self.assertEqual(uri(report.to_sarif([finding], "sample-app")), "sample-app/config.py")

    def test_cli_derives_the_prefix_from_where_it_was_started(self):
        with tempfile.TemporaryDirectory() as out, \
                mock.patch("bridge.cli.os.getcwd", return_value=ROOT):
            buffer = StringIO()
            with redirect_stdout(buffer):
                cli.main(["scan", APP, "--demo", "--out", out])
            with open(os.path.join(out, "report.sarif")) as handle:
                results = json.load(handle)["runs"][0]["results"]
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
        self.assertIn("sample-app/config.py", uris)
        self.assertTrue(all(u.startswith("sample-app/") for u in uris))


class WorkflowTests(unittest.TestCase):
    """Guards the pipeline file. We cannot run GitHub from here, but we can make sure
    nobody breaks its safety properties by accident. Skipped if PyYAML is missing."""

    @classmethod
    def setUpClass(cls):
        try:
            import yaml
        except ImportError:
            raise unittest.SkipTest("PyYAML not installed")
        path = os.path.join(ROOT, ".github", "workflows", "securebridge.yml")
        with open(path) as handle:
            cls.text = handle.read()
            cls.wf = yaml.safe_load(cls.text)

    def test_default_permissions_are_read_only(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})

    def test_only_the_scan_job_may_write_security_events(self):
        self.assertNotIn("permissions", self.wf["jobs"]["test"])
        self.assertEqual(self.wf["jobs"]["scan"]["permissions"]["security-events"], "write")

    def test_scan_waits_for_the_tests(self):
        self.assertEqual(self.wf["jobs"]["scan"]["needs"], "test")

    def test_publishing_steps_still_run_when_the_scan_blocks(self):
        steps = {s.get("name", ""): s for s in self.wf["jobs"]["scan"]["steps"]}
        for name in ("Show the report in the run summary",
                     "Upload findings to the Security tab",
                     "Keep the reports as a download"):
            self.assertIn("always()", steps[name]["if"], name)
        # The scan step itself must NOT swallow its failure, or blocking would do nothing.
        scan_step = steps["Run SecureBridge"]
        self.assertNotIn("continue-on-error", scan_step)
        self.assertNotIn("if", scan_step)

    def test_scanner_versions_are_empty_or_a_real_version_number(self):
        for key in ("GITLEAKS_VERSION", "TRIVY_VERSION"):
            self.assertRegex(self.wf["env"][key], r"^(\d+\.\d+\.\d+)?$")

    def test_versions_used_are_always_printed_so_runs_can_be_pinned_later(self):
        steps = {s.get("name", ""): s for s in self.wf["jobs"]["scan"]["steps"]}
        shown = steps["Show scanner versions"]["run"]
        for tool in ("gitleaks version", "trivy --version", "semgrep --version"):
            self.assertIn(tool, shown)

    def test_install_step_fails_loudly_and_lists_release_files(self):
        steps = {s.get("name", ""): s for s in self.wf["jobs"]["scan"]["steps"]}
        install = steps["Install the scanners"]["run"]
        self.assertIn("set -euo pipefail", install)
        self.assertIn("gh release view", install)  # prints real file names on failure


@unittest.skipIf(os.name == "nt", "uses small shell-script stand-ins for gitleaks")
class SelfTestTests(unittest.TestCase):
    """The canary: a scanner that says '0 findings' must prove it can find something."""

    HEALTHY = """#!/bin/sh
src=.
while [ $# -gt 0 ]; do
  case "$1" in --report-path) out="$2";; --source) src="$2";; esac
  shift
done
hit=$(grep -rl 'ghp_' "$src" 2>/dev/null | head -1)
if [ -n "$hit" ]; then
  printf '[{"RuleID":"github-pat","File":"%s","StartLine":1,"Description":"token"}]' "$hit" > "$out"
else
  printf '[]' > "$out"
fi
"""
    BLIND = """#!/bin/sh
while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && out="$2"; shift; done
printf '[]' > "$out"
"""

    def run_with(self, script, folder):
        from bridge.runner import run_real
        with tempfile.TemporaryDirectory() as bin_dir:
            path = os.path.join(bin_dir, "gitleaks")
            with open(path, "w") as handle:
                handle.write(script)
            os.chmod(path, 0o755)
            env = {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}
            with mock.patch.dict(os.environ, env):
                return run_real("gitleaks", folder)

    def test_a_scanner_that_finds_the_canary_is_trusted(self):
        with tempfile.TemporaryDirectory() as clean:
            result = self.run_with(self.HEALTHY, clean)
        self.assertEqual(result.status, "ok")
        self.assertIn("self-test passed", result.detail)
        self.assertEqual(result.findings, [])

    def test_a_blind_scanner_reporting_zero_is_marked_failed_not_clean(self):
        result = self.run_with(self.BLIND, APP)
        self.assertEqual(result.status, "failed")
        self.assertIn("self-test FAILED", result.detail)

    def test_real_findings_are_kept_even_when_the_self_test_fails(self):
        script = self.BLIND.replace(
            "printf '[]'",
            """printf '[{"RuleID":"github-pat","File":"config.py","StartLine":5}]'""")
        # This stand-in always reports config.py, even for the canary folder (which has
        # canary.py only), so the self-test must still fail while the finding survives.
        result = self.run_with(script, APP)
        self.assertEqual(result.status, "failed")
        self.assertEqual(len(result.findings), 1)

    def test_the_canary_token_has_the_right_shape_and_is_not_in_the_sample_app(self):
        from bridge.runner import _CANARY_TOKEN
        self.assertRegex(_CANARY_TOKEN, r"^ghp_[0-9a-zA-Z]{36}$")
        with open(os.path.join(APP, "config.py")) as handle:
            self.assertNotIn(_CANARY_TOKEN, handle.read())
        with open(os.path.join(ROOT, "bridge", "runner.py")) as handle:
            self.assertNotIn(_CANARY_TOKEN, handle.read())  # split so we do not scan ourselves


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
