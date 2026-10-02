"""
Secure counterparts of the patterns in app.py.

This file exists to show the scanners do NOT flag correct code
(a quick false-positive check). It must produce zero findings.
"""
import ast
import hashlib
import json
import os
import sqlite3
import subprocess
from html import escape


def get_user(username: str):
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # Parameterized query: data is never part of the SQL text.
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


def ping(host: str) -> int:
    # Argument list, no shell: the host can never become shell syntax.
    return subprocess.run(["ping", "-c", "1", host], check=False).returncode


def calc(expression: str):
    # Only literals are accepted, nothing is executed.
    return ast.literal_eval(expression)


def load_session(raw: bytes):
    # JSON cannot instantiate arbitrary objects.
    return json.loads(raw)


def greet(name: str) -> str:
    return "<h1>Hello " + escape(name) + "</h1>"


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_api_key() -> str:
    # Secrets come from the environment, never from source code.
    return os.environ["API_KEY"]
