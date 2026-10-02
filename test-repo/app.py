"""
INTENTIONALLY VULNERABLE DEMO APPLICATION - DO NOT DEPLOY.

Each route contains one deliberate weakness so the scanning pipeline has
something predictable to detect. Nothing in this file should be reused.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("demo.db")


@app.route("/user")
def get_user():
    # VULNERABLE (CWE-89): user input formatted directly into the SQL string.
    username = request.args.get("username")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return str(cursor.fetchall())


@app.route("/search")
def search():
    # VULNERABLE (CWE-89): query built by concatenation, then executed.
    term = request.args.get("q")
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    # VULNERABLE (CWE-78): user input reaches a shell command.
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "done"


@app.route("/lookup")
def lookup():
    # VULNERABLE (CWE-78): shell=True with an interpolated command.
    domain = request.args.get("domain")
    output = subprocess.check_output(f"nslookup {domain}", shell=True)
    return output


@app.route("/calc")
def calc():
    # VULNERABLE (CWE-95): evaluating user-supplied text as Python code.
    expression = request.args.get("expr")
    return str(eval(expression))


@app.route("/load", methods=["POST"])
def load_session():
    # VULNERABLE (CWE-502): unpickling untrusted bytes.
    return str(pickle.loads(request.data))


@app.route("/greet")
def greet():
    # VULNERABLE (CWE-79): request data reflected into HTML without escaping.
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"


def hash_password(password: str) -> str:
    # VULNERABLE (CWE-327): MD5 is not suitable for password hashing.
    return hashlib.md5(password.encode()).hexdigest()
