import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/rm")
def rm():
    path = request.args["path"]  # gt:source
    os.system("rm -rf " + path)  # gt:sink
    return "ok"
