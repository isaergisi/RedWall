# sqli, safe
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    q = request.args.get('q')
    if q not in ('a', 'b'):
        return ''
    db.execute("SELECT * FROM t WHERE c = '" + q + "'")
