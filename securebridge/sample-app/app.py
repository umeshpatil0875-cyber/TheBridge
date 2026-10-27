"""Intentionally vulnerable demo app. DO NOT deploy it anywhere.

Every flaw in this file is on purpose, so the scanners have something to find.
"""
import sqlite3
import subprocess

from flask import Flask, request

from config import DB_PATH

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    db = sqlite3.connect(DB_PATH)
    # FLAW 1: SQL injection. User input is pasted straight into the query text.
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return str(db.execute(query).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FLAW 2: command injection. User input reaches a shell.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


if __name__ == "__main__":
    # FLAW 3: debug mode exposes an interactive console to anyone who can reach it.
    app.run(host="0.0.0.0", debug=True)
