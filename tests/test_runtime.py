"""Tests for the running-system layer: the ZAP adapter, the demo target app, and wiring."""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from bridge import adapters, cli, layers, report, runner  # noqa: E402
from bridge.models import Finding  # noqa: E402
from bridge.policy import evaluate, load_policy  # noqa: E402

APP = os.path.join(ROOT, "sample-app")
spec = importlib.util.spec_from_file_location("runtime_target", os.path.join(ROOT, "runtime-target", "app.py"))
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


def zap_fixture():
    with open(os.path.join(ROOT, "fixtures", "zap.json")) as handle:
        return json.load(handle)


class ZapAdapterTests(unittest.TestCase):
    def test_one_finding_per_alert_with_severity_mapped_from_riskcode(self):
        findings = adapters.parse_zap(zap_fixture())
        self.assertEqual(len(findings), 7)
        by_rule = {f.rule_id: f for f in findings}
        self.assertEqual(by_rule["10038-1"].severity, "medium")
        self.assertEqual(by_rule["10021-1"].severity, "low")
        for f in findings:
            self.assertEqual((f.tool, f.category), ("zap", "runtime"))
            self.assertTrue(f.file.startswith("http://"))

    def test_html_is_stripped_from_text(self):
        for f in adapters.parse_zap(zap_fixture()):
            self.assertNotIn("<", f.description + f.fix + f.title)

    def test_the_number_of_urls_is_mentioned(self):
        csp = next(f for f in adapters.parse_zap(zap_fixture()) if f.rule_id == "10038-1")
        self.assertIn("3 URL(s)", csp.description)

    def test_odd_input_never_crashes(self):
        for data in (None, {}, {"site": None}, {"site": [{}]}, {"site": {"alerts": [{}]}},
                     {"site": [{"alerts": [{"riskcode": "x", "count": "many", "instances": []}]}]}):
            adapters.parse_zap(data)
        (f,) = adapters.parse_zap({"site": [{"alerts": [{"riskcode": "9"}]}]})
        self.assertEqual(f.severity, "info")  # unknown risk is shown, never dropped or blocking

    def test_findings_are_assigned_to_the_runtime_layer(self):
        for f in adapters.parse_zap(zap_fixture()):
            self.assertEqual(layers.classify(f, APP), "runtime")


class ZapRunTests(unittest.TestCase):
    def test_a_missing_or_unsafe_target_is_skipped(self):
        for url in ("", "ftp://x", "--evil", "file:///etc/passwd"):
            self.assertEqual(runner.run_zap(url).status, "skipped", url)

    def test_missing_docker_is_skipped_not_clean(self):
        with mock.patch("bridge.runner.shutil.which", return_value=None):
            run = runner.run_zap("http://127.0.0.1:8081")
        self.assertEqual(run.status, "skipped")
        self.assertIn("docker", run.detail)

    def test_a_site_that_was_not_crawled_is_a_failure_not_a_clean_result(self):
        def fake(command, **kwargs):
            work = command[command.index("-v") + 1].split(":")[0]
            with open(os.path.join(work, "zap.json"), "w") as handle:
                json.dump({"site": []}, handle)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("bridge.runner.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("bridge.runner.subprocess.run", side_effect=fake):
            run = runner.run_zap("http://127.0.0.1:8081")
        self.assertEqual(run.status, "failed")

    def test_a_good_report_is_parsed_and_the_command_is_safe(self):
        seen = {}
        def fake(command, **kwargs):
            seen["command"] = command
            work = command[command.index("-v") + 1].split(":")[0]
            with open(os.path.join(work, "zap.json"), "w") as handle:
                json.dump(zap_fixture(), handle)
            return mock.Mock(returncode=2, stdout="", stderr="")  # 2 = warnings, still a good run
        with mock.patch("bridge.runner.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("bridge.runner.subprocess.run", side_effect=fake):
            run = runner.run_zap("http://127.0.0.1:8081")
        self.assertEqual((run.status, len(run.findings)), ("ok", 7))
        command = seen["command"]
        self.assertIsInstance(command, list)  # never a shell string
        self.assertIn("-I", command)
        self.assertEqual(command[command.index("-t") + 1], "http://127.0.0.1:8081")

    def test_a_crash_exit_code_is_a_failure(self):
        with mock.patch("bridge.runner.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("bridge.runner.subprocess.run",
                           return_value=mock.Mock(returncode=3, stdout="", stderr="boom")):
            self.assertEqual(runner.run_zap("http://127.0.0.1:8081").status, "failed")


class RuntimeLayerTests(unittest.TestCase):
    def scan(self, *extra):
        with tempfile.TemporaryDirectory() as out, redirect_stdout(StringIO()) as buffer:
            code = cli.main(["scan", APP, "--demo", "--out", out, *extra])
            with open(os.path.join(out, "report.json")) as h:
                data = json.load(h)
            with open(os.path.join(out, "report.sarif")) as h:
                sarif = json.load(h)
        return code, data, sarif, buffer.getvalue()

    def test_without_a_target_the_runtime_layer_stays_not_scanned(self):
        _, data, _, _ = self.scan()
        row = next(r for r in data["layers"] if r["layer"] == "runtime")
        self.assertEqual(row["status"], "not scanned")
        self.assertNotIn("zap", [s["name"] for s in data["scanners"]])

    def test_with_a_target_the_runtime_layer_is_checked_and_defective(self):
        _, data, _, _ = self.scan("--target-url", "http://127.0.0.1:8081")
        row = next(r for r in data["layers"] if r["layer"] == "runtime")
        self.assertEqual(row["status"], "DEFECTIVE")  # medium findings block at runtime
        self.assertEqual(row["checked_by"], ["zap"])
        self.assertEqual(row["findings"], 7)

    def test_runtime_findings_are_left_out_of_sarif_because_they_have_no_file(self):
        _, _, sarif, _ = self.scan("--target-url", "http://127.0.0.1:8081")
        for result in sarif["runs"][0]["results"]:
            self.assertNotEqual(result["properties"]["tool"], "zap")

    def test_the_policy_blocks_medium_runtime_findings_but_not_low_ones(self):
        policy = load_policy(os.path.join(ROOT, "policy.json"))
        def finding(sev):
            return Finding("zap", "runtime", "r", sev, "t", "http://x/", layer="runtime")
        self.assertTrue(evaluate([finding("medium")], policy).blocked)
        self.assertFalse(evaluate([finding("low")], policy).blocked)


class TargetAppTests(unittest.TestCase):
    """The demo web app must really have (or lack) the protections it claims."""

    def serve(self, mode):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), target.make_handler(mode))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(self, url):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status, r.headers
        except urllib.error.HTTPError as error:
            return error.code, error.headers

    def test_weak_mode_has_no_protections_and_a_plain_cookie(self):
        status, headers = self.get(self.serve("weak") + "/")
        self.assertEqual(status, 200)
        for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            self.assertIsNone(headers[name], name)
        self.assertNotIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("Python", headers["Server"])

    def test_hardened_mode_has_the_protections_on_every_response_including_errors(self):
        base = self.serve("hardened")
        for path, expected in (("/", 200), ("/about", 200), ("/nope", 404)):
            status, headers = self.get(base + path)
            self.assertEqual(status, expected)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["X-Frame-Options"], "DENY")
        _, headers = self.get(base + "/")
        for flag in ("HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(flag, headers["Set-Cookie"])
        self.assertNotIn("Python", headers["Server"])

    def test_the_target_listens_only_on_localhost_by_default(self):
        with open(os.path.join(ROOT, "runtime-target", "app.py")) as handle:
            spec_text = handle.read()
        self.assertIn('default="127.0.0.1"', spec_text)


if __name__ == "__main__":
    unittest.main()
