import os


class DiskStore:
    def __init__(self, root):
        self.root = root

    def read(self, name):
        path = os.path.join(self.root, os.path.basename(name))
        with open(path, "rb") as fh:  # gt:sink
            return fh.read()
