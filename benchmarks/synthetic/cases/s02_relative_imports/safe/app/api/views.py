from flask import Blueprint, request

from ..core.reports import report

bp = Blueprint("api", __name__)


@bp.route("/report")
def show():
    month = request.args["month"]  # gt:source
    return {"data": report(month)}
