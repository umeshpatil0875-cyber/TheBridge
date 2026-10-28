import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from bridge import cli, store  # noqa: E402
from bridge.grouping import group_findings  # noqa: E402

APP = os.path.join(ROOT, "sample-app")


def f(**kw):
    base = dict(tool="semgrep", category="code", rule_id="r", severity="high", title="t",
                file="app.py", line=1, package="", fix="", layer="source")
    base.update(kw)
    return base


class GroupingTests(unittest.TestCase):
    def test_rules_on_the_same_line_become_one_place(self):
        groups = group_findings([f(rule_id="a", line=28), f(rule_id="b", line=28), f(rule_id="c", line=28)])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 3)
        self.assertEqual(groups[0]["where"], "app.py:28")

    def test_different_lines_stay_separate(self):
        self.assertEqual(len(group_findings([f(line=20), f(line=21)])), 2)

    def test_cves_in_one_package_become_one_place(self):
        deps = [f(tool="trivy", category="dependency", package="flask", file="requirements.txt",
                  rule_id=f"CVE-{i}", line=None, layer="dependencies") for i in range(5)]
        deps.append(f(tool="trivy", category="dependency", package="jinja2", file="requirements.txt",
                      rule_id="CVE-9", line=None, layer="dependencies"))
        groups = group_findings(deps)
        self.assertEqual(sorted(g["count"] for g in groups), [1, 5])
        self.assertEqual({g["kind"] for g in groups}, {"package"})

    def test_nothing_is_lost_the_counts_add_up(self):
        items = [f(line=i % 3, rule_id=str(i)) for i in range(10)]
        self.assertEqual(sum(g["count"] for g in group_findings(items)), 10)

    def test_worst_severity_leads_and_sets_the_order(self):
        groups = group_findings([f(line=1, severity="low"), f(line=1, severity="critical"),
                                 f(line=2, severity="medium")])
        self.assertEqual([g["worst_severity"] for g in groups], ["critical", "medium"])

    def test_tools_and_titles_are_collected_without_repeats(self):
        g = group_findings([f(line=3, tool="trivy", title="same"), f(line=3, tool="semgrep", title="same"),
                            f(line=3, tool="semgrep", title="other")])[0]
        self.assertEqual(g["tools"], ["semgrep", "trivy"])
        self.assertEqual(g["titles"].count("same"), 1)

    def test_unknown_severity_does_not_crash(self):
        self.assertEqual(len(group_findings([f(severity="weird")])), 1)

    def test_empty_input(self):
        self.assertEqual(group_findings([]), [])


class GroupingIntegrationTests(unittest.TestCase):
    def scan(self):
        with tempfile.TemporaryDirectory() as out, redirect_stdout(StringIO()) as buffer:
            cli.main(["scan", APP, "--demo", "--out", out])
            with open(os.path.join(out, "report.json")) as h:
                data = json.load(h)
            with open(os.path.join(out, "report.md")) as h:
                md = h.read()
        return data, md, buffer.getvalue()

    def test_reports_show_places_to_fix_and_keep_every_finding(self):
        data, md, text = self.scan()
        self.assertEqual(sum(p["count"] for p in data["problems"]), len(data["findings"]))
        self.assertLess(data["problem_count"], len(data["findings"]))
        self.assertIn("Things to fix", md)
        self.assertIn("place(s) to fix", text)

    def test_grouping_does_not_change_the_verdict(self):
        data, _, text = self.scan()
        self.assertEqual(data["verdict"], "blocked")
        self.assertIn("VERDICT: BLOCKED", text)

    def test_the_api_scan_includes_the_grouped_view(self):
        data, _, _ = self.scan()
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.connect(os.path.join(tmp, "g.db"))
            pid = store.authenticate(conn, store.create_project(conn, "p"))
            saved = store.save_scan(conn, pid, data)
            scan = store.get_scan(conn, pid, saved["id"])
            conn.close()
        self.assertEqual(sum(p["count"] for p in scan["problems"]), len(scan["findings"]))


if __name__ == "__main__":
    unittest.main()
