"""A tiny web app for SecureBridge's last layer: the RUNNING system.

Standard library only, so it starts anywhere with: python runtime-target/app.py
It has two modes (so you can prove the gate in both directions, like sample-app and
sample-app-fixed do for the code layers):

  --mode weak       the way many apps ship: no security headers, a cookie that
                    JavaScript can read, and a server banner that names its version.
  --mode hardened   the same pages with the standard protections switched on.

LESSON 28 explains what each header does. DO NOT deploy this anywhere: it is a target
for scanners, not a real application.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGES = {
    "/": b"<html><head><title>Demo shop</title></head><body><h1>Demo shop</h1>"
         b"<p><a href='/about'>About</a> | <a href='/login'>Log in</a></p></body></html>",
    "/about": b"<html><head><title>About</title></head><body><p>A page for scanners to find."
              b"</p><a href='/'>Home</a></body></html>",
    "/login": b"<html><head><title>Log in</title></head><body><form method='post' action='/login'>"
              b"<input name='user'><input name='password' type='password'>"
              b"<button>Log in</button></form></body></html>",
}

# In hardened mode the login form carries an anti-CSRF token: a secret value the server
# checks on submit, so another website cannot make your browser send the form for you.
# (A real app creates a fresh random token per session; this demo uses a fixed one.)
HARDENED_LOGIN = PAGES["/login"].replace(
    b"<button>", b"<input type='hidden' name='csrf_token' value='demo-csrf-token'><button>")

HARDENED_HEADERS = {
    # Only load scripts, styles and images from this same site; never be shown in a frame.
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",  # the older way of saying "no frames", for old browsers
    "X-Content-Type-Options": "nosniff",  # browsers must trust the declared content type
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",  # do not keep copies of pages in shared caches
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def make_handler(mode):
    class Handler(BaseHTTPRequestHandler):
        if mode == "hardened":
            server_version = "web"  # do not announce what software and version we run
            sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def end_headers(self):
            # Runs for EVERY response, including error pages, so protections never have gaps.
            if mode == "hardened":
                for name, value in HARDENED_HEADERS.items():
                    self.send_header(name, value)
            super().end_headers()

        def do_GET(self):
            route = self.path.split("?")[0]
            page = HARDENED_LOGIN if (mode == "hardened" and route == "/login") else PAGES.get(route)
            if page is None:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if mode == "hardened":
                self.send_header("Set-Cookie", "session=demo; Path=/; HttpOnly; Secure; SameSite=Strict")
            else:
                self.send_header("Set-Cookie", "session=demo; Path=/")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self):
            self.send_error(405)

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["weak", "hardened"], default="weak")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    print(f"runtime-target ({args.mode}) on http://{args.host}:{args.port}", flush=True)
    ThreadingHTTPServer((args.host, args.port), make_handler(args.mode)).serve_forever()


if __name__ == "__main__":
    main()
