# sqli, safe
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    q = int(request.args.get('q'))
    db.execute(f'SELECT * FROM t WHERE id = {q}')
