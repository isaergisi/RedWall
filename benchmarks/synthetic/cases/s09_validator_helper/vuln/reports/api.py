import sqlite3

from flask import Flask, abort, request

from reports.checks import is_known_table

app = Flask(__name__)


@app.route("/count")
def count():
    table = request.args["table"]  # gt:source
    if not is_known_table(table):
        abort(400)
    cur = sqlite3.connect("r.db").cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table}")  # gt:sink
    return {"n": cur.fetchone()[0]}
