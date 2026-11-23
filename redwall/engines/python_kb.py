"""Knowledge base for the Python engine: sources, sinks, sanitizers, propagators.

Everything here is plain data so rules can be reviewed (and extended) without
reading the analyzer. Names are fully qualified after import-alias resolution,
e.g. ``from flask import redirect`` makes ``redirect(...)`` resolve to
``flask.redirect``.

*Sink kinds* name a vulnerability class. A sanitizer clears a value only for the
kinds it protects against: ``html.escape`` makes a value safe in an HTML page
(``xss``) but not in a shell command (``cmdi``). The special kind ``*`` means
"safe everywhere" (e.g. ``int(x)``).
"""

from __future__ import annotations

from typing import Dict, FrozenSet

ALL = "*"

# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------

REQUEST_ATTRS = {
    "args", "form", "values", "json", "cookies", "headers", "files", "data",
    "get_json", "get_data", "view_args", "query_string", "stream",
    "GET", "POST", "COOKIES", "FILES", "META", "body",
    "query_params", "path_params",
}
SOURCE_CALLS = {"input", "raw_input"}
SOURCE_ATTRS = {"sys.argv", "sys.stdin"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}

# --------------------------------------------------------------------------
# Sanitizers (name -> sink kinds they clear)
# --------------------------------------------------------------------------

_HTML = frozenset({"xss"})
SANITIZERS: Dict[str, FrozenSet[str]] = {
    # Type conversions: the result cannot carry an injection payload.
    **{n: frozenset({ALL}) for n in (
        "int", "float", "bool", "len", "abs", "round", "ord", "hash", "id", "complex",
        "uuid.UUID", "ipaddress.ip_address", "ipaddress.ip_network",
        "datetime.date.fromisoformat", "datetime.datetime.fromisoformat",
    )},
    # HTML / XML escaping.
    **{n: _HTML for n in (
        "html.escape", "markupsafe.escape", "flask.escape", "jinja2.escape", "cgi.escape",
        "django.utils.html.escape", "django.utils.html.conditional_escape",
        "xml.sax.saxutils.escape", "xml.sax.saxutils.quoteattr", "bleach.clean",
        "werkzeug.utils.escape",
    )},
    # Shell quoting.
    "shlex.quote": frozenset({"cmdi"}),
    "pipes.quote": frozenset({"cmdi"}),
    "shlex.join": frozenset({"cmdi"}),
    # File names.
    "werkzeug.utils.secure_filename": frozenset({"path"}),
    "os.path.basename": frozenset({"path"}),
    # LDAP.
    "ldap3.utils.conv.escape_filter_chars": frozenset({"ldap"}),
    "ldap.filter.escape_filter_chars": frozenset({"ldap"}),
    "ldap.dn.escape_dn_chars": frozenset({"ldap"}),
    "ldap3.utils.dn.escape_rdn": frozenset({"ldap"}),
    # URLs.
    "urllib.parse.quote": frozenset({"xss", "path"}),
    "urllib.parse.quote_plus": frozenset({"xss", "path", "cmdi"}),
    "flask.url_for": frozenset({ALL}),
    "re.escape": frozenset({"regex"}),
}

# Last-component names that sanitize when nothing more specific is known
# (project helpers such as ``escape_for_html``).
SANITIZER_SUFFIXES: Dict[str, FrozenSet[str]] = {
    "secure_filename": frozenset({"path"}),
    "escape_filter_chars": frozenset({"ldap"}),
    "escape_dn_chars": frozenset({"ldap"}),
}


def name_sanitizer(name: str) -> FrozenSet[str]:
    """Heuristic sink kinds cleared by a function judged from its name alone."""
    last = name.rsplit(".", 1)[-1].lower()
    if last in SANITIZER_SUFFIXES:
        return SANITIZER_SUFFIXES[last]
    if "escape" in last and ("html" in last or "xml" in last or last == "escape"):
        return _HTML
    if last in ("quote", "shell_quote", "shellquote"):
        return frozenset({"cmdi"})
    return frozenset()


# Methods that return a bool / number / position, never an injectable string.
SCALAR_METHODS = {
    "startswith", "endswith", "isdigit", "isdecimal", "isnumeric", "isalpha", "isalnum",
    "isidentifier", "isascii", "isspace", "islower", "isupper", "istitle", "find", "rfind",
    "index", "rindex", "count", "__len__", "is_absolute", "is_relative_to",
}
STRING_BUILD_METHODS = {"format", "join", "replace", "format_map"}
# Pure ``str`` methods we can fold when receiver and arguments are constant.
FOLDABLE_STR_METHODS = {
    "lower", "upper", "strip", "lstrip", "rstrip", "startswith", "endswith", "find",
    "replace", "count", "isdigit", "isalnum", "isalpha", "title", "capitalize", "split",
    "join", "format", "encode", "decode", "casefold", "removeprefix", "removesuffix",
}

# Calls whose result does not carry the taint of their arguments (sinks that
# return file handles, rendered templates, HTTP responses ...).
NON_PROPAGATING = {
    "open", "io.open", "codecs.open", "os.open", "os.path.exists", "os.path.isfile",
    "os.path.isdir", "os.listdir", "flask.render_template", "flask.render_template_string",
    "render_template", "flask.jsonify", "jsonify", "json.dumps", "flask.Markup",
    "markupsafe.Markup", "jinja2.Markup", "Markup", "isinstance", "hasattr", "callable",
    "type", "hashlib.md5", "hashlib.sha1", "hashlib.sha256", "hashlib.new",
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.Popen",
    "os.system", "eval", "exec", "compile",
}
# Pure data transformations: constant in, constant out.
PURE_PREFIXES = ("base64.", "binascii.", "codecs.encode", "codecs.decode", "urllib.parse.", "zlib.",
                 "html.unescape", "json.loads", "string.", "textwrap.", "unicodedata.")

NON_PROPAGATING_PREFIXES = ("requests.", "httpx.", "urllib.request.", "hashlib.", "secrets.", "random.")

# --------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra"}
SQL_FUNCS = {"sqlalchemy.text", "sqlalchemy.sql.text", "text"}
CMD_FUNCS = {
    "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
    "os.spawnl", "os.spawnlp", "os.spawnv", "os.spawnvp", "os.execl", "os.execlp",
    "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
}
SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
}
# ``[shell, "-c", command]``: the element after the flag is interpreted as code.
SHELL_FLAGS = {"-c", "/c", "/C", "-Command", "-command"}
SHELL_BINARIES = {
    "sh", "bash", "zsh", "ksh", "dash", "csh", "tcsh", "fish", "busybox", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "python", "python3", "perl", "ruby", "node", "php",
}
CODE_FUNCS = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
DESER_FUNCS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "_pickle.loads",
    "dill.loads", "dill.load", "marshal.loads", "marshal.load", "shelve.open",
    "jsonpickle.decode", "pandas.read_pickle", "yaml.unsafe_load",
}
YAML_SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
SSTI_FUNCS = {"flask.render_template_string", "render_template_string", "jinja2.Template", "Template"}
MARKUP_FUNCS = {"markupsafe.Markup", "flask.Markup", "jinja2.Markup", "Markup"}
PATH_FUNCS = {
    "open", "io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
    "os.listdir", "os.scandir", "os.stat", "os.mkdir", "os.makedirs", "os.rename", "os.replace",
    "os.path.exists", "os.path.lexists", "os.path.isfile", "os.path.isdir", "os.path.getsize",
    "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move",
    "shutil.copytree", "flask.send_file", "send_file", "pathlib.Path", "pathlib.PurePath",
    "fileinput.input", "tarfile.open", "zipfile.ZipFile",
}
# A file handle or HTTP response does not carry the taint of the path it was opened with.
NON_PROPAGATING |= PATH_FUNCS - {"pathlib.Path", "pathlib.PurePath"}

# Methods that touch the file system when called on a (tainted) path object.
PATH_METHODS = {
    "exists", "is_file", "is_dir", "read_text", "read_bytes", "write_text", "write_bytes",
    "open", "unlink", "rmdir", "mkdir", "touch", "iterdir", "stat", "rename", "glob", "rglob",
}
SSRF_PREFIXES = ("requests.", "httpx.", "urllib.request.urlopen", "urllib3.request")
SSRF_FUNCS = {"urlopen"}
WEAK_HASHES = {"md5", "sha1"}

REDIRECT_FUNCS = {
    "flask.redirect", "werkzeug.utils.redirect", "django.shortcuts.redirect",
    "django.http.HttpResponseRedirect", "django.http.HttpResponsePermanentRedirect",
    "starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse",
}
RESPONSE_FUNCS = {
    "flask.make_response", "flask.Response", "werkzeug.wrappers.Response",
    "django.http.HttpResponse", "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse",
}
# Response constructors that are a sink on their own (no route decorator needed).
DIRECT_XSS_FUNCS = {"django.http.HttpResponse", "starlette.responses.HTMLResponse",
                    "fastapi.responses.HTMLResponse"}

LDAP_SEARCH_METHODS = {
    # method -> argument positions / keywords holding the base DN and the filter
    "search": ((0, 1), ("search_base", "search_filter")),               # ldap3
    "search_s": ((0, 2), ("base", "filterstr")),                       # python-ldap
    "search_st": ((0, 2), ("base", "filterstr")),
    "search_ext": ((0, 2), ("base", "filterstr")),
    "search_ext_s": ((0, 2), ("base", "filterstr")),
    "search_paged": ((0, 1), ("search_base", "search_filter")),
}

XPATH_FUNCS = {
    "lxml.etree.XPath", "lxml.etree.ETXPath", "lxml.etree.XPathEvaluator",
    "elementpath.select", "elementpath.iter_select", "elementpath.Selector",
}
XPATH_METHODS = {"xpath"}
ETREE_FIND_METHODS = {"find", "findall", "iterfind", "findtext"}

# XML parsing calls that accept a parser object.
SAX_PARSER_FACTORIES = {"xml.sax.make_parser"}
SAX_EXTERNAL_FEATURES = {
    "xml.sax.handler.feature_external_ges", "xml.sax.handler.feature_external_pes",
    "feature_external_ges", "feature_external_pes",
    "http://xml.org/sax/features/external-general-entities",
    "http://xml.org/sax/features/external-parameter-entities",
}
LXML_PARSERS = {"lxml.etree.XMLParser", "lxml.etree.XMLPullParser", "lxml.etree.XSLTAccessControl"}
XML_PARSE_METHODS = {"parse", "feed", "parseString"}

# ``random`` module functions that are predictable (CWE-330). ``SystemRandom``
# is not listed: it reads os.urandom.
WEAK_RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices", "sample", "shuffle", "getrandbits",
    "randbytes", "uniform", "triangular", "normalvariate", "gauss", "betavariate",
    "expovariate", "gammavariate", "lognormvariate", "vonmisesvariate", "paretovariate",
    "weibullvariate", "binomialvariate",
}
SECURITY_WORDS = (
    "token", "secret", "password", "passwd", "session", "cookie", "nonce", "salt", "otp",
    "csrf", "auth", "remember", "apikey", "api_key", "reset", "verify", "key",
)

SESSION_OBJECTS = {"flask.session", "session"}

# Methods that store their argument inside the receiver (taint by side effect).
MUTATORS = {
    "append", "extend", "insert", "add", "update", "write", "writelines", "set", "setdefault",
    "put", "put_nowait", "appendleft", "extendleft", "push", "__setitem__", "read_string",
    "read_dict",
}
