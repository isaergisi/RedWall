from flask import Flask, request

from dyn import actions

app = Flask(__name__)


@app.route("/action")
def action():
    fn = getattr(actions, request.args["name"])
    return fn(str(int(request.args["arg"]))) or ""  # gt:source
