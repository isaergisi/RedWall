# deserialization, vulnerable
from flask import request
import os, subprocess, sqlite3, pickle, json, shlex

db = sqlite3.connect(':memory:')


def handler():
    return pickle.loads(request.get_data())
