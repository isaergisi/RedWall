"""Phase 1: new rule families and the precision features behind them."""

import textwrap
from pathlib import Path

from redwall.models import Confidence
from redwall.scanner import ScanOptions, scan


def _scan(tmp_path: Path, code: str, name: str = "app.py"):
    (tmp_path / name).write_text(textwrap.dedent(code))
    return scan(tmp_path, options=ScanOptions(engines=["python-ast"])).findings


def _rules(findings):
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------
# New rule families
# --------------------------------------------------------------------------


def test_reflected_xss_in_flask_view(tmp_path):
    findings = _scan(tmp_path, """
        from flask import Flask, request, make_response
        import html
        app = Flask(__name__)

        @app.route("/a")
        def a():
            return "Hello " + request.args["name"]

        @app.route("/b")
        def b():
            return "Hello " + html.escape(request.args["name"])

        @app.route("/c")
        def c():
            return make_response(("ok", {"X-Name": request.args["name"]}))  # header, not body

        @app.route("/d")
        def d():
            return {"name": request.args["name"]}  # JSON

        @app.route("/e/<int:item>")
        def e(item):
            return f"item {item}"
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-XSS-RESPONSE", 8)]
    assert findings[0].confidence is Confidence.HIGH


def test_escaping_is_sink_specific(tmp_path):
    findings = _scan(tmp_path, """
        import html, os
        from flask import request
        def f():
            name = html.escape(request.args["n"])
            os.system("echo " + name)
    """)
    [f] = findings
    assert f.rule_id == "RW-PY-CMDI"
    assert any("safe for xss only" in s.note for s in f.trace)


def test_ldap_injection_and_escape(tmp_path):
    findings = _scan(tmp_path, """
        import ldap3
        from ldap3.utils.conv import escape_filter_chars
        from flask import request
        def f(conn):
            uid = request.args["uid"]
            conn.search("ou=users", f"(uid={uid})")
            conn.search("ou=users", f"(uid={escape_filter_chars(uid)})")
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-LDAPI", 7)]


def test_xpath_injection_and_variables(tmp_path):
    findings = _scan(tmp_path, """
        import lxml.etree
        from flask import request
        def f(root):
            uid = request.args["uid"]
            root.xpath(f"//user[@id='{uid}']")
            root.xpath("//user[@id=$uid]", uid=uid)
            root.xpath(f"//user[@id='{uid.replace(chr(39), '&apos;')}']")
            root.xpath(f"//user[@id='{uid.replace(\"'\", '&apos;')}']")
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-XPATHI", 6), ("RW-PY-XPATHI", 8)]


def test_xxe_only_when_external_entities_are_enabled(tmp_path):
    findings = _scan(tmp_path, """
        import xml.sax, xml.sax.handler, xml.dom.minidom
        import lxml.etree
        from flask import request
        def f():
            data = request.data
            p = xml.sax.make_parser()
            xml.dom.minidom.parseString(data, p)
            q = xml.sax.make_parser()
            q.setFeature(xml.sax.handler.feature_external_ges, True)
            xml.dom.minidom.parseString(data, q)
            unsafe = lxml.etree.XMLParser(resolve_entities=True)
            lxml.etree.fromstring(data, unsafe)
            lxml.etree.fromstring("<a/>", unsafe)
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-XXE", 11), ("RW-PY-XXE", 13)]


def test_weak_random(tmp_path):
    findings = _scan(tmp_path, """
        import random, secrets
        def make_reset_token():
            return str(random.getrandbits(64))
        def shuffle_cards(cards):
            random.shuffle(cards)
        def good():
            return secrets.token_hex(16), random.SystemRandom().random()
    """)
    assert [(f.rule_id, f.line, f.confidence) for f in findings] == [
        ("RW-PY-WEAKRAND", 4, Confidence.MEDIUM), ("RW-PY-WEAKRAND", 6, Confidence.LOW)]


def test_cookie_secure_flag(tmp_path):
    findings = _scan(tmp_path, """
        def f(resp, jar, cookie):
            resp.set_cookie("sid", "1", secure=False)
            resp.set_cookie("sid", "1")
            resp.set_cookie("sid", "1", secure=True, httponly=True)
            resp.set_cookie("sid", "1", **opts)
            jar.set_cookie(cookie)  # requests' CookieJar API, not a response
    """)
    assert [(f.line, f.confidence) for f in findings] == [(3, Confidence.HIGH), (4, Confidence.MEDIUM)]


def test_open_redirect_and_allow_list_guard(tmp_path):
    findings = _scan(tmp_path, """
        from flask import redirect, request
        from urllib.parse import urlparse
        def a():
            return redirect(request.args["next"])
        def b():
            nxt = request.args["next"]
            if urlparse(nxt).netloc not in ("example.com",):
                return redirect("/")
            return redirect(nxt)
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-OPENREDIRECT", 5)]


def test_trust_boundary(tmp_path):
    findings = _scan(tmp_path, """
        from flask import session, request
        def f():
            session["user"] = request.form["user"]
            session[request.form["k"]] = "1"
            session["role"] = "guest"
            session["n"] = int(request.form["n"])
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-TRUSTBOUND", 4), ("RW-PY-TRUSTBOUND", 5)]


# --------------------------------------------------------------------------
# Precision: constant folding, containers, guards, summaries
# --------------------------------------------------------------------------


def test_constant_conditions_prune_dead_branches(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def f():
            p = request.args["p"]
            num = 106
            a = "safe" if (7 * 42) - num > 200 else p      # p (188 > 200 is false)
            b = "safe" if (7 * 18) + num > 200 else p      # "safe"
            if "should" not in "This should never happen":
                c = "x"
            else:
                c = p                                      # taken
            os.system(a)
            os.system(b)
            os.system(c)
    """)
    assert [f.line for f in findings] == [13, 15]


def test_match_on_a_constant(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def f(which):
            p = request.args["p"]
            guess = "ABC"[1]
            match guess:
                case "A":
                    bar = p
                case "B":
                    bar = "bob"
                case _:
                    bar = p
            os.system(bar)
    """)
    assert findings == []


def test_dict_list_and_configparser_slots(tmp_path):
    findings = _scan(tmp_path, """
        import configparser, os
        from flask import request
        def f():
            p = request.args["p"]
            m = {}
            m["a"] = "safe"
            m["b"] = p
            os.system(m["a"])
            os.system(m["b"])                  # 10
            lst = ["safe", p, "moresafe"]
            lst.pop(0)
            os.system(lst[1])
            os.system(lst[0])                  # 14
            conf = configparser.ConfigParser()
            conf.add_section("s")
            conf.set("s", "a", "safe")
            conf.set("s", "b", p)
            os.system(conf.get("s", "a"))
            os.system(conf.get("s", "b"))      # 20
    """)
    assert [f.line for f in findings] == [10, 14, 20]


def test_shell_wrapper_list(tmp_path):
    findings = _scan(tmp_path, """
        import os, subprocess
        from flask import request
        def f():
            h = request.args["h"]
            args = []
            if os.name == "nt":
                args += ["cmd.exe", "/c"]
            else:
                args += ["sh", "-c"]
            args.append("ping " + h)
            subprocess.run(args)
            subprocess.run(["ping", "-c", "1", h])     # -c is ping's count, not a shell
    """)
    assert [f.line for f in findings] == [12]


def test_deny_list_guard_clears_only_its_kind(tmp_path):
    findings = _scan(tmp_path, """
        from flask import Flask, request
        app = Flask(__name__)
        @app.route("/r")
        def r():
            name = request.args["f"]
            if "../" in name:
                return "no"
            data = open("files/" + name).read()
            return "read " + name                        # still XSS
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-XSS-RESPONSE", 10)]


def test_prefix_check_needs_a_normalised_path(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        BASE = "/srv/files"
        def raw():
            p = os.path.join(BASE, request.args["f"])
            if not p.startswith(BASE):
                return None
            return open(p)                          # 9: "../" survives
        def normalised():
            p = os.path.realpath(os.path.join(BASE, request.args["f"]))
            if not p.startswith(BASE):
                return None
            return open(p)
    """)
    assert [(f.rule_id, f.line) for f in findings] == [("RW-PY-PATH", 9)]


def test_allow_list_guard_inside_branch(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        ALLOWED = {"ls", "id"}
        def f():
            cmd = request.args["c"]
            if cmd in ALLOWED:
                os.system(cmd)
            os.system(cmd)        # 9: outside the check
    """)
    assert [f.line for f in findings] == [9]


def test_helper_summaries_across_files(tmp_path):
    (tmp_path / "helpers.py").write_text(textwrap.dedent("""
        class Wrapper:
            def __init__(self, request):
                self.request = request
            def get_param(self, name):
                return self.request.args.get(name)
            def get_safe_value(self, name):
                return "bar"

        def passthrough(x):
            return x
    """))
    findings = _scan(tmp_path, """
        import os
        import helpers
        from flask import request
        def f():
            w = helpers.Wrapper(request)
            os.system(w.get_param("a"))                     # 7: source via helper
            os.system(w.get_safe_value("a"))                # constant
            os.system(helpers.passthrough(w.get_param("a")))  # 9
    """)
    assert [(f.line, f.confidence) for f in findings] == [(7, Confidence.HIGH), (9, Confidence.HIGH)]


def test_break_keeps_assignments_made_in_the_loop(tmp_path):
    findings = _scan(tmp_path, """
        import os
        from flask import request
        def f():
            param = ""
            for name in request.form.keys():
                if "x" in request.form.getlist(name):
                    param = name
                    break
            os.system("echo " + param)
    """)
    assert [f.line for f in findings] == [10]


def test_literal_data_is_not_reported_for_deserialization(tmp_path):
    findings = _scan(tmp_path, """
        import pickle, base64
        def f(blob):
            pickle.loads(base64.b64decode("gASVAAAAAAAAAACMBGRhdGGULg=="))
            pickle.loads(blob)
    """)
    assert [(f.line, f.confidence) for f in findings] == [(5, Confidence.MEDIUM)]
