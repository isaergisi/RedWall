# sqli, vulnerable
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    q = request.args.get('q')
    db.execute("SELECT * FROM t WHERE c = '%s'" % q)
