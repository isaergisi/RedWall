KNOWN = {"orders", "customers", "invoices"}


def is_known_table(name):
    return name in KNOWN
