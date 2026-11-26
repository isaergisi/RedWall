from . import storage


def report(month):
    sql = "SELECT * FROM sales WHERE month = ?"  # gt:sink
    return storage.query(sql, (month,))  # gt:sink
