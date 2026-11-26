import os

from files.disk import DiskStore


def get_store():
    return DiskStore(os.environ.get("DATA_DIR", "/srv/data"))
