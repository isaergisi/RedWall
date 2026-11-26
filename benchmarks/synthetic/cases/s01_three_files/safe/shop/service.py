from shop import db


def find_user(name):
    query = "SELECT * FROM users WHERE name = ?"  # gt:sink
    return db.run_params(query, (name,))
