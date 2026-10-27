"""The FIXED version of sample-app: the same app with every planted flaw repaired.

Scan this folder to watch the verdict turn from BLOCKED to PASSED (the "green" half
of the red-to-green proof). Compare it with ../sample-app to see each fix.
"""
import os
import sqlite3
import subprocess

from flask import Flask, request

from config import DB_PATH

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    db = sqlite3.connect(DB_PATH)
    # FIX 1: a parameterized query. The database treats `name` as data, never as SQL.
    return str(db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX 2: no shell, and the input is checked against a strict pattern first.
    if not host.replace(".", "").isalnum():
        return "bad host", 400
    return subprocess.check_output(["ping", "-c", "1", host])


if __name__ == "__main__":
    # FIX 3: no debug mode, and only listen on localhost unless told otherwise.
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), debug=False)
