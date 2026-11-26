import subprocess


def ping(host):
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)  # gt:sink
    return out.stdout
