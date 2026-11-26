import sqlite3


def run(query):
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute(query)  # gt:sink-shared
    return cur.fetchall()


def run_params(query, params):
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute(query, params)
    return cur.fetchall()
