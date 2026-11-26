import os


def restart(arg):
    os.system("service restart " + arg)  # gt:sink


def status(arg):
    return "ok"
