import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/rm")
def rm():
    path = request.args["path"]  # gt:source
    subprocess.run(["rm", "-rf", "--", path], check=True)  # gt:sink
    return "ok"
