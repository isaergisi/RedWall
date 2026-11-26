from flask import Flask, request

from engines.mysql import MysqlEngine

app = Flask(__name__)


@app.post("/tables")
def tables():
    db_name = request.form["db"]  # gt:source
    return {"tables": MysqlEngine().tables(db_name)}
