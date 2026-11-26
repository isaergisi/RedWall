import subprocess


class CommandMixin:
    def execute(self, cmd):
        return subprocess.check_output(cmd, shell=True)  # gt:sink-shared
