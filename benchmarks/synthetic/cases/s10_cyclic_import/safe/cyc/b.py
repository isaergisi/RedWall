from cyc import a


def process(arg):
    a.run("convert %d.png out.png" % int(arg))  # gt:sink
