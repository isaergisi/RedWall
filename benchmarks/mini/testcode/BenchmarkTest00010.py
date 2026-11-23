# cmdi, safe
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    h = request.args.get('h')
    os.system('ping ' + shlex.quote(h))
