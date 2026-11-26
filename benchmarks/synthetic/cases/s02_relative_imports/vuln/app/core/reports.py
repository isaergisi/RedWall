from . import storage


def report(month):
    sql = f"SELECT * FROM sales WHERE month = '{month}'"  # gt:sink
    return storage.query(sql)  # gt:sink
