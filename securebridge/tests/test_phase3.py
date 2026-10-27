"""Tests for phase 3: the database, the API and the upload. Everything runs locally
against a temporary database and a real server on a free port."""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from bridge import cli, server, store, upload  # noqa: E402

APP = os.path.join(ROOT, "sample-app")


def demo_report(drop=0):
    """A real report.json made by the real engine in demo mode."""
    with tempfile.TemporaryDirectory() as out, redirect_stdout(StringIO()):
        cli.main(["scan", APP, "--demo", "--out", out])
        with open(os.path.join(out, "report.json")) as handle:
            report = json.load(handle)
    if drop:
        report["findings"] = report["findings"][drop:]
    return report


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = store.connect(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.conn.close)

    def project(self, name="alpha"):
        token = store.create_project(self.conn, name)
        return token, store.authenticate(self.conn, token)

    def test_the_real_token_is_never_stored(self):
        token, _ = self.project()
        rows = self.conn.execute("SELECT * FROM projects").fetchall()
        self.assertNotIn(token, json.dumps([tuple(r) for r in rows]))
        self.assertTrue(token.startswith("sb_"))

    def test_wrong_empty_or_missing_tokens_are_rejected(self):
        self.project()
        for bad in ("", "sb_wrong", None):
            self.assertIsNone(store.authenticate(self.conn, bad))

    def test_duplicate_project_names_are_refused(self):
        self.project()
        with self.assertRaises(store.ValidationError):
            store.create_project(self.conn, "alpha")

    def test_a_scan_is_saved_with_all_its_findings(self):
        _, pid = self.project()
        report = demo_report()
        saved = store.save_scan(self.conn, pid, report, "abc123", "main")
        scan = store.get_scan(self.conn, pid, saved["id"])
        self.assertEqual(len(scan["findings"]), len(report["findings"]))
        self.assertEqual(scan["verdict"], report["verdict"])
        self.assertEqual(scan["commit_sha"], "abc123")
        self.assertIsNone(saved["new"])  # first scan: nothing to compare with

    def test_the_second_scan_says_what_is_new_and_what_was_fixed(self):
        _, pid = self.project()
        store.save_scan(self.conn, pid, demo_report())
        saved = store.save_scan(self.conn, pid, demo_report(drop=3))
        self.assertEqual(saved["fixed"], 3)
        self.assertEqual(saved["new"], 0)
        again = store.save_scan(self.conn, pid, demo_report())
        self.assertEqual(again["new"], 3)

    def test_projects_cannot_see_each_others_scans(self):
        _, a = self.project("alpha")
        _, b = self.project("beta")
        saved = store.save_scan(self.conn, a, demo_report())
        self.assertIsNone(store.get_scan(self.conn, b, saved["id"]))
        self.assertEqual(store.list_scans(self.conn, b), [])
        self.assertEqual(store.trend(self.conn, b), [])
        self.assertEqual(len(store.list_scans(self.conn, a)), 1)

    def test_diff_only_compares_within_one_project(self):
        _, a = self.project("alpha")
        _, b = self.project("beta")
        store.save_scan(self.conn, a, demo_report())
        saved = store.save_scan(self.conn, b, demo_report())
        self.assertIsNone(saved["new"])  # beta's first scan, whatever alpha has

    def test_bad_reports_are_rejected_and_nothing_is_saved(self):
        _, pid = self.project()
        good = demo_report()
        broken = []
        r = json.loads(json.dumps(good)); r["verdict"] = "maybe"; broken.append(r)
        r = json.loads(json.dumps(good)); r["findings"][0]["severity"] = "hgih"; broken.append(r)
        r = json.loads(json.dumps(good)); del r["findings"][0]["rule_id"]; broken.append(r)
        r = json.loads(json.dumps(good)); r["findings"] = "nope"; broken.append(r)
        broken.append([1, 2, 3])
        for report in broken:
            with self.assertRaises(store.ValidationError):
                store.save_scan(self.conn, pid, report)
        self.assertEqual(store.list_scans(self.conn, pid), [])

    def test_sql_injection_in_text_fields_is_just_text(self):
        _, pid = self.project()
        report = demo_report()
        report["findings"][0]["title"] = "x'); DROP TABLE scans;--"
        store.save_scan(self.conn, pid, report, "'; DROP TABLE scans;--")
        self.assertEqual(len(store.list_scans(self.conn, pid)), 1)

    def test_trend_runs_oldest_to_newest(self):
        _, pid = self.project()
        first = store.save_scan(self.conn, pid, demo_report())["id"]
        second = store.save_scan(self.conn, pid, demo_report(drop=2))["id"]
        self.assertEqual([t["id"] for t in store.trend(self.conn, pid)], [first, second])
        self.assertEqual(store.list_scans(self.conn, pid)[0]["id"], second)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "api.db")
        conn = store.connect(cls.db)
        cls.token_a = store.create_project(conn, "alpha")
        cls.token_b = store.create_project(conn, "beta")
        conn.close()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cls.db))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, token=None, body=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_health_needs_no_login(self):
        self.assertEqual(self.call("GET", "/healthz"), (200, {"status": "ok"}))

    def test_everything_else_needs_a_valid_token(self):
        for method, path in (("GET", "/api/v1/scans"), ("GET", "/api/v1/trend"),
                             ("GET", "/api/v1/scans/1"), ("POST", "/api/v1/scans")):
            self.assertEqual(self.call(method, path)[0], 401, path)
            self.assertEqual(self.call(method, path, "sb_wrong")[0], 401, path)

    def test_upload_then_read_back(self):
        status, saved = self.call("POST", "/api/v1/scans", self.token_a,
                                  {"report": demo_report(), "commit": "c1", "branch": "main"})
        self.assertEqual(status, 201)
        status, scan = self.call("GET", f"/api/v1/scans/{saved['id']}", self.token_a)
        self.assertEqual(status, 200)
        self.assertEqual(scan["branch"], "main")
        self.assertTrue(scan["findings"])
        status, listing = self.call("GET", "/api/v1/scans", self.token_a)
        self.assertIn(saved["id"], [s["id"] for s in listing["scans"]])
        status, trend = self.call("GET", "/api/v1/trend", self.token_a)
        self.assertEqual(status, 200)
        self.assertIn("blocking_count", trend["trend"][0])

    def test_another_project_gets_404_not_the_data(self):
        _, saved = self.call("POST", "/api/v1/scans", self.token_a, {"report": demo_report()})
        status, _ = self.call("GET", f"/api/v1/scans/{saved['id']}", self.token_b)
        self.assertEqual(status, 404)

    def test_bad_input_gets_clear_errors(self):
        self.assertEqual(self.call("POST", "/api/v1/scans", self.token_a, raw=b"not json")[0], 400)
        self.assertEqual(self.call("POST", "/api/v1/scans", self.token_a, {"x": 1})[0], 400)
        bad = demo_report(); bad["findings"][0]["severity"] = "hgih"
        status, error = self.call("POST", "/api/v1/scans", self.token_a, {"report": bad})
        self.assertEqual(status, 422)
        self.assertIn("severity", error["error"])
        self.assertEqual(self.call("GET", "/api/v1/scans/abc", self.token_a)[0], 400)
        self.assertEqual(self.call("GET", "/api/v1/scans?limit=x", self.token_a)[0], 400)
        self.assertEqual(self.call("GET", "/api/v1/nothing", self.token_a)[0], 404)

    def test_oversized_bodies_are_refused(self):
        old = server.MAX_BODY
        server.MAX_BODY = 100
        try:
            status, _ = self.call("POST", "/api/v1/scans", self.token_a, {"report": demo_report()})
        finally:
            server.MAX_BODY = old
        self.assertEqual(status, 413)

    def test_cli_upload_stores_the_scan_and_keeps_the_exit_code(self):
        with tempfile.TemporaryDirectory() as out:
            buffer = StringIO()
            with redirect_stdout(buffer):
                code = cli.main(["scan", APP, "--demo", "--out", out,
                                 "--upload-url", self.base, "--token", self.token_a])
        self.assertEqual(code, 1)  # still BLOCKED
        self.assertIn("upload: saved as scan #", buffer.getvalue())

    def test_a_dead_server_or_bad_token_never_changes_the_verdict(self):
        with tempfile.TemporaryDirectory() as out, redirect_stdout(StringIO()):
            dead = cli.main(["scan", APP, "--demo", "--out", out,
                             "--upload-url", "http://127.0.0.1:1", "--token", "x"])
            wrong = cli.main(["scan", APP, "--demo", "--out", out,
                              "--upload-url", self.base, "--token", "sb_wrong"])
            none = cli.main(["scan", APP, "--demo", "--out", out, "--upload-url", self.base])
        self.assertEqual((dead, wrong, none), (1, 1, 1))

    def test_upload_helper_reports_what_changed(self):
        text = json.dumps(demo_report())
        upload.upload_report(self.base, self.token_b, text)
        ok, message = upload.upload_report(self.base, self.token_b, text)
        self.assertTrue(ok)
        self.assertIn("0 new, 0 fixed", message)


if __name__ == "__main__":
    unittest.main()
