# Each line marked "expect: RULE-ID" must produce exactly that finding.
import hashlib
import os
import pickle
import sqlite3
import subprocess as sp
import tempfile
from os import system

import requests
import yaml
from flask import Flask, Markup, render_template_string, request, send_file

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def user():
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + uid
    cur = db.cursor()
    cur.execute(query)  # expect: RW-PY-SQLI
    cur.execute(f"DELETE FROM users WHERE name = '{request.form['name']}'")  # expect: RW-PY-SQLI
    return "ok"


def report(table):
    db.execute("SELECT count(*) FROM %s" % table)  # expect: RW-PY-SQLI


@app.route("/ping")
def ping():
    host = request.args["host"]
    os.system("ping -c 1 " + host)  # expect: RW-PY-CMDI
    sp.run(f"nslookup {host}", shell=True)  # expect: RW-PY-CMDI
    system(host)  # expect: RW-PY-CMDI
    return "pong"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))  # expect: RW-PY-CODEI


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # expect: RW-PY-DESER
    cfg = yaml.load(open("config.yml"))  # expect: RW-PY-DESER
    return str(obj) + str(cfg)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    page = render_template_string("<h1>Hello " + name + "</h1>")  # expect: RW-PY-SSTI
    return Markup(f"<p>{name}</p>") + page  # expect: RW-PY-XSS


@app.route("/files/<filename>")
def download(filename):
    return send_file(filename)  # expect: RW-PY-PATH


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    return requests.get(url, timeout=5).text  # expect: RW-PY-SSRF


def misc():
    requests.get("https://internal.example", verify=False)  # expect: RW-PY-TLS
    digest = hashlib.md5(b"data").hexdigest()  # expect: RW-PY-WEAKHASH
    path = tempfile.mktemp()  # expect: RW-PY-TEMPFILE
    return digest, path


if __name__ == "__main__":
    app.run(debug=True)  # expect: RW-PY-DEBUG
