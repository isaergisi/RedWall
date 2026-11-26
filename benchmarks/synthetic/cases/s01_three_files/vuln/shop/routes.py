from flask import Flask, request

from shop.service import find_user

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name", "")  # gt:source
    return {"rows": find_user(name)}
