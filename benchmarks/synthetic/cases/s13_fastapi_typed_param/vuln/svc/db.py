import sqlite3


def fetch(sql):
    cur = sqlite3.connect("s.db").cursor()
    cur.execute(sql)  # gt:sink-shared
    return cur.fetchall()
