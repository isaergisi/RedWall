from werkzeug.utils import secure_filename


def clean_name(name):
    return secure_filename(name.strip().lower())
