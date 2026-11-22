# sqli, vulnerable
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    q = request.form['q']
    sql = f"SELECT * FROM t WHERE c = '{q}'"
    db.execute(sql)
