"""A small web API in front of the database, using only Python's standard library.

LESSON 24 (what an API is): other programs (the pipeline, later a dashboard, later your
customers' own tools) cannot open your database file. They talk to an API: they send an
HTTP request ("POST this scan") and get an answer back as JSON. The API is the front
door, and it decides who may come in.

  GET  /healthz              is the service alive (no login needed)
  POST /api/v1/scans         upload a report.json   (returns the new scan, and what changed)
  GET  /api/v1/scans         list this project's scans, newest first
  GET  /api/v1/scans/<id>    one scan with all its findings
  GET  /api/v1/trend         verdict + counts per scan, oldest first (for charts)
  GET  /api/v1/insights      the same plus counts by severity/layer/tool and new/fixed
  GET  /dashboard            the dashboard page (asks you for the token; no data without it)

Login: send the project token as   Authorization: Bearer <token>
The token decides which project you are, so you can only ever see your own scans.

HONEST LIMITS (read before putting this on the internet): this server speaks plain HTTP,
has no rate limiting and one process. Put it behind HTTPS (a reverse proxy or a cloud
platform) and a proper web framework before real customers use it. It is a learning
version of the same design.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import store

MAX_BODY = 5 * 1024 * 1024  # 5 MB
DASHBOARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")

# LESSON 25 (browser safety headers): the dashboard page runs code in your browser, so we
# tell the browser exactly what it may do: only our own script and styles, only talk to
# this same server, never be embedded in another site, never guess content types.
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; "
                               "style-src 'unsafe-inline'; connect-src 'self'; "
                               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def make_handler(db_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureBridge"

        def log_message(self, fmt, *args):  # keep the console quiet; tokens never logged
            pass

        # -- helpers --
        def _send(self, status: int, payload) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _page(self) -> None:
            try:
                with open(DASHBOARD, "rb") as handle:
                    body = handle.read()
            except OSError:
                return self._send(404, {"error": "dashboard file missing"})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for name, value in PAGE_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _project(self, conn):
            header = self.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else ""
            return store.authenticate(conn, token)

        # -- routes --
        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/healthz":
                return self._send(200, {"status": "ok"})
            if url.path in ("/", "/dashboard"):
                return self._page()
            conn = store.connect(db_path)
            try:
                project = self._project(conn)
                if project is None:
                    return self._send(401, {"error": "missing or invalid token"})
                query = parse_qs(url.query)
                try:
                    limit = int(query.get("limit", ["20"])[0])
                except ValueError:
                    return self._send(400, {"error": "limit must be a number"})
                if url.path == "/api/v1/scans":
                    return self._send(200, {"scans": store.list_scans(conn, project, limit)})
                if url.path == "/api/v1/insights":
                    return self._send(200, {"insights": store.insights(conn, project, limit)})
                if url.path == "/api/v1/trend":
                    return self._send(200, {"trend": store.trend(conn, project, limit)})
                if url.path.startswith("/api/v1/scans/"):
                    tail = url.path.rsplit("/", 1)[1]
                    if not tail.isdigit():
                        return self._send(400, {"error": "scan id must be a number"})
                    scan = store.get_scan(conn, project, int(tail))
                    # Someone else's scan looks exactly like one that does not exist.
                    return self._send(200, scan) if scan else self._send(404, {"error": "not found"})
                return self._send(404, {"error": "not found"})
            finally:
                conn.close()

        def do_POST(self):
            if urlparse(self.path).path != "/api/v1/scans":
                return self._send(404, {"error": "not found"})
            conn = store.connect(db_path)
            try:
                project = self._project(conn)
                if project is None:
                    return self._send(401, {"error": "missing or invalid token"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return self._send(400, {"error": "bad Content-Length"})
                if length <= 0 or length > MAX_BODY:
                    return self._send(413, {"error": f"body must be 1 byte to {MAX_BODY} bytes"})
                try:
                    body = json.loads(self.rfile.read(length))
                except json.JSONDecodeError:
                    return self._send(400, {"error": "body is not valid JSON"})
                if not isinstance(body, dict) or "report" not in body:
                    return self._send(400, {"error": "body must look like {\"report\": {...}}"})
                try:
                    saved = store.save_scan(conn, project, body["report"],
                                            body.get("commit", ""), body.get("branch", ""))
                except store.ValidationError as error:
                    return self._send(422, {"error": str(error)})
                return self._send(201, saved)
            finally:
                conn.close()

    return Handler


def serve(db_path: str, host: str, port: int) -> None:
    store.connect(db_path).close()  # make sure the tables exist
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"SecureBridge API on http://{host}:{port}  (database: {db_path})")
    httpd.serve_forever()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bridge.server")
    parser.add_argument("--db", default="securebridge.db")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-project", help="make a project and print its token once")
    create.add_argument("name")
    run = sub.add_parser("serve", help="start the API")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    if args.command == "create-project":
        conn = store.connect(args.db)
        try:
            token = store.create_project(conn, args.name)
        except store.ValidationError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(f"Project '{args.name}' created.\nAPI token (shown once, save it now):\n{token}")
        return 0
    serve(args.db, args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
