import subprocess


def extract_to(target):
    subprocess.run(["tar", "xf", "upload.tar", "-C", target], check=True)  # gt:sink
