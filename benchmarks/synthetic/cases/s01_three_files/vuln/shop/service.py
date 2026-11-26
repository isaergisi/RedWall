from shop import db


def find_user(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name  # gt:sink
    return db.run(query)
