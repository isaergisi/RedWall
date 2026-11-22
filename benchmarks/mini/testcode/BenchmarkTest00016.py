# codeinj, safe
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    expr = request.args.get('e')
    return json.loads(expr)
