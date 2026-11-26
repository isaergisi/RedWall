def join_parts(parts, acc="/srv/data"):
    if not parts:
        return acc
    return join_parts(parts[1:], acc + "/" + str(int(parts[0])))


def read_nested(parts):
    with open(join_parts(parts)) as fh:  # gt:sink
        return fh.read()
