# pathtraver, safe
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    return open('/srv/static/index.html').read()
