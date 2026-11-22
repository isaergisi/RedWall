# Safe counterparts: RedWall must report nothing in this file.
import hashlib
import os
import shlex
import sqlite3
import subprocess

import yaml
from flask import Flask, render_template, request

app = Flask(__name__)
db = sqlite3.connect("app.db")
TABLE = "users"


@app.route("/user")
def user():
    uid = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))
    db.execute("SELECT * FROM " + TABLE)
    num = int(request.args["n"])
    db.execute(f"SELECT * FROM users LIMIT {num}")
    return render_template("user.html", uid=uid)


@app.route("/ping")
def ping():
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host], check=False)
    os.system("ping -c 1 " + shlex.quote(host))
    os.system("uptime")
    return "pong"


def config():
    with open("config.yml") as fh:
        data = yaml.safe_load(fh)
    other = yaml.load(fh, Loader=yaml.SafeLoader)
    return data, other


def checksum(blob):
    return hashlib.md5(blob, usedforsecurity=False).hexdigest(), hashlib.sha256(blob).hexdigest()


def local_files(name):
    # Not a route: parameters are not treated as user input.
    return open(name).read()


def suppressed():
    eval("1 + 1")
    os.system(os.environ["CMD"])  # redwall: ignore[RW-PY-CMDI]
