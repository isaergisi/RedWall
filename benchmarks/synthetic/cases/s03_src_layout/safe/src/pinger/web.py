from flask import Flask, request

from pinger.netutil import ping

app = Flask(__name__)


@app.post("/ping")
def do_ping():
    host = request.form["host"]  # gt:source
    return ping(host)
