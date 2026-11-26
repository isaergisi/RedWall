from flask import Flask, request

from rec.paths import read_nested

app = Flask(__name__)


@app.route("/nested")
def nested():
    parts = request.args.getlist("p")  # gt:source
    return read_nested(parts)
