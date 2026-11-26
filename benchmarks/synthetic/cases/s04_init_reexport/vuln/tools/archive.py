import os


def extract_to(target):
    os.system("tar xf upload.tar -C " + target)  # gt:sink
