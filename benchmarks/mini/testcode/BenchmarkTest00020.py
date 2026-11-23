# cmdi, vulnerable
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    h = request.args.get('h')
    cmd = ['sh', '-c', 'ping ' + h]
    subprocess.call(cmd)
