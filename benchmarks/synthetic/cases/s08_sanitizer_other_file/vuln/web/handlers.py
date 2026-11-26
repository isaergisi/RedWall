import os

from flask import Flask, request

from web.names import clean_name

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/avatar")
def avatar():
    name = clean_name(request.args["name"])  # gt:source
    with open(os.path.join(UPLOADS, name), "rb") as fh:  # gt:sink
        return fh.read()
