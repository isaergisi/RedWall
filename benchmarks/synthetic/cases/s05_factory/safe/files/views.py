from flask import Flask, request

from files.backends import get_store

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args["file"]  # gt:source
    return get_store().read(name)
