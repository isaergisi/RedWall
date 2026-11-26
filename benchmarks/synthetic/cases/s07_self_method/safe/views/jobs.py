import shlex

from flask import request
from flask.views import MethodView

from views.base import CommandMixin


class JobView(CommandMixin, MethodView):
    def build(self, job):
        return "systemctl restart " + shlex.quote(job)  # gt:sink

    def post(self):
        job = request.form["job"]  # gt:source
        return self.execute(self.build(job))
