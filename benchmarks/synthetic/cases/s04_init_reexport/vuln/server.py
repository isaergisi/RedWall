from flask import Flask, request

from tools import extract_to

app = Flask(__name__)


@app.route("/extract")
def extract():
    target = request.args.get("dir")  # gt:source
    extract_to(target)
    return "ok"
