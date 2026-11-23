# pathtraver, vulnerable
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    name = request.args.get('f')
    return open(name).read()
