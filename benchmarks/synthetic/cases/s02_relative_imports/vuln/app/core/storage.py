import sqlite3


def query(sql, params=()):
    cur = sqlite3.connect("r.db").cursor()
    cur.execute(sql, params)  # gt:sink-shared
    return cur.fetchall()
