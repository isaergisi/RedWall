import os

from flask import Flask, request

from cyc import b

app = Flask(__name__)


def run(cmd):
    os.system(cmd)  # gt:sink-shared


@app.route("/go")
def go():
    b.process(request.args["arg"])  # gt:source
    return "ok"
