"""Why is this finding still open? Deterministic, evidence-based explanations.

Every sentence here is built from facts stage 1 recorded (the trace, the sink,
the flow level, the rule) and from what the Python engine actually knows how
to recognise as a fix. When RedWall cannot prove something, the text says so
instead of guessing. English (``en``) and Turkish (``tr``) are available.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ..models import Confidence, Finding, ScoreFactor
from .scoring import DATAFLOW_KINDS, LOCAL, REMOTE, REPO, ROUTE, Score

LANGS = ("en", "tr")

_IMPACT = {
    "en": {
        "rce": "impact: an attacker could run code or commands on the server",
        "data": "impact: an attacker could read or change data the application can reach",
        "internal": "impact: an attacker could make the server call internal services",
        "credential": "impact: a leaked credential gives direct access to another system",
        "browser": "impact: an attacker could run script in a victim's browser",
        "transport": "impact: traffic or cookies can be read or changed on the network",
        "debugger": "impact: an interactive debugger may be reachable",
        "phishing": "impact: users can be sent to an attacker's site from a trusted link",
        "predictable": "impact: generated values can be predicted",
        "integrity": "impact: untrusted data is treated as trusted session state",
        "crypto": "impact: a broken hash weakens whatever relies on it",
        "race": "impact: a temporary file can be hijacked between creation and use",
        "other": "impact: derived from the rule severity",
    },
    "tr": {
        "rce": "etki: saldırgan sunucuda kod veya komut çalıştırabilir",
        "data": "etki: saldırgan uygulamanın erişebildiği veriyi okuyup değiştirebilir",
        "internal": "etki: saldırgan sunucuya iç servisleri çağırtabilir",
        "credential": "etki: sızan kimlik bilgisi başka bir sisteme doğrudan erişim verir",
        "browser": "etki: saldırgan kurbanın tarayıcısında betik çalıştırabilir",
        "transport": "etki: trafik veya çerezler ağda okunup değiştirilebilir",
        "debugger": "etki: etkileşimli hata ayıklayıcıya erişilebilir",
        "phishing": "etki: kullanıcılar güvenilen bir bağlantıdan saldırganın sitesine yönlendirilebilir",
        "predictable": "etki: üretilen değerler tahmin edilebilir",
        "integrity": "etki: güvenilmeyen veri güvenilir oturum verisi gibi kullanılır",
        "crypto": "etki: kırık özet algoritması ona dayanan her şeyi zayıflatır",
        "race": "etki: geçici dosya oluşturma ile kullanım arasında ele geçirilebilir",
        "other": "etki: kural şiddetinden alındı",
    },
}

_EVIDENCE = {
    "en": {
        ("flow", "traced"): "evidence: user input traced to the sink",
        ("flow", "built"): "evidence: sink receives a string built from non-constant parts",
        ("flow", "unknown"): "evidence: sink receives a value of unknown origin",
        ("plain", "high"): "evidence: exact pattern match",
        ("plain", "medium"): "evidence: likely pattern match",
        ("plain", "low"): "evidence: weak pattern match",
    },
    "tr": {
        ("flow", "traced"): "kanıt: kullanıcı girdisi sink'e kadar izlendi",
        ("flow", "built"): "kanıt: sink'e sabit olmayan parçalardan kurulmuş bir metin gidiyor",
        ("flow", "unknown"): "kanıt: sink'e kaynağı bilinmeyen bir değer gidiyor",
        ("plain", "high"): "kanıt: kesin kalıp eşleşmesi",
        ("plain", "medium"): "kanıt: olası kalıp eşleşmesi",
        ("plain", "low"): "kanıt: zayıf kalıp eşleşmesi",
    },
}

_EXPOSURE = {
    "en": {
        REMOTE: "exposure: data comes from an HTTP request (reachable remotely)",
        ROUTE: "exposure: code runs inside an HTTP route handler",
        LOCAL: "exposure: data comes from the local user (input()/argv/stdin)",
        REPO: "exposure: anyone who can read the repository can use it",
    },
    "tr": {
        REMOTE: "maruziyet: veri bir HTTP isteğinden geliyor (uzaktan erişilebilir)",
        ROUTE: "maruziyet: kod bir HTTP rota fonksiyonunun içinde çalışıyor",
        LOCAL: "maruziyet: veri yerel kullanıcıdan geliyor (input()/argv/stdin)",
        REPO: "maruziyet: depoyu okuyabilen herkes kullanabilir",
    },
}

_CONTEXT = {
    "en": "context: test, example or documentation code (ranked lower, still listed)",
    "tr": "bağlam: test, örnek veya doküman kodu (daha aşağıda sıralandı, yine listelendi)",
}

# What the Python engine recognises as a fix for each sink kind. "Not found" is
# only claimed for things the engine actually models.
_MITIGATIONS = {
    "en": {
        "sqli": "a parameterised query (constant SQL text, values passed separately), an int()/UUID conversion, "
                "or an allow-list check such as `if x not in ALLOWED: return`",
        "cmdi": "shlex.quote(), an argument list without shell=True, an int() conversion, or an allow-list check",
        "code": "ast.literal_eval()/json.loads() instead of eval/exec, an int() conversion, or an allow-list check",
        "deser": "a data-only format (json, yaml.safe_load) for this call",
        "ssti": "a fixed template with user data passed only as context variables",
        "xss": "html.escape()/markupsafe.escape(), an auto-escaping template, or a JSON response",
        "path": "secure_filename()/os.path.basename(), a normalise-then-startswith(base) check, "
                "a `'..' in x` rejection, or an allow-list check",
        "ssrf": "an allow-list check on the host or URL before the request",
        "ldap": "escape_filter_chars()/escape_dn_chars()",
        "xpath": "XPath variables instead of string building",
        "xxe": "a parser with external entities disabled (or defusedxml)",
        "redirect": "url_for(), a relative-path check, or an allow-listed host check",
        "trustbound": "a type conversion or allow-list check before the value is stored",
    },
    "tr": {
        "sqli": "parametreli sorgu (sabit SQL metni, değerler ayrı verilir), int()/UUID dönüşümü "
                "veya `if x not in IZINLI: return` gibi bir izin listesi kontrolü",
        "cmdi": "shlex.quote(), shell=True olmadan argüman listesi, int() dönüşümü veya izin listesi kontrolü",
        "code": "eval/exec yerine ast.literal_eval()/json.loads(), int() dönüşümü veya izin listesi kontrolü",
        "deser": "bu çağrı için yalnızca veri taşıyan bir format (json, yaml.safe_load)",
        "ssti": "sabit bir şablon ve kullanıcı verisinin yalnızca bağlam değişkeni olarak verilmesi",
        "xss": "html.escape()/markupsafe.escape(), otomatik kaçışlı şablon veya JSON yanıtı",
        "path": "secure_filename()/os.path.basename(), önce normalleştirip sonra startswith(taban) kontrolü, "
                "`'..' in x` reddi veya izin listesi kontrolü",
        "ssrf": "istekten önce ana makine veya URL için izin listesi kontrolü",
        "ldap": "escape_filter_chars()/escape_dn_chars()",
        "xpath": "metin birleştirme yerine XPath değişkenleri",
        "xxe": "dış varlıkları kapalı bir ayrıştırıcı (veya defusedxml)",
        "redirect": "url_for(), göreli yol kontrolü veya izinli ana makine kontrolü",
        "trustbound": "değer saklanmadan önce tür dönüşümü veya izin listesi kontrolü",
    },
}

_NON_FLOW = {
    "en": {
        "tls": "`verify=False` (or an equivalent option) is written in the call itself; it does not depend on "
               "configuration, so every run skips certificate checks.",
        "debug": "debug=True is passed as a literal; RedWall cannot see whether this line runs only in development.",
        "cookie": "The cookie is set without secure=True (or with secure=False) on this call.",
        "weakrand": "The `random` module is used where the surrounding names suggest a security value "
                    "(token, password, key ...).",
        "weakhash": "MD5/SHA-1 is called without usedforsecurity=False, so RedWall cannot tell that the use is "
                    "not security related.",
        "tempfile": "tempfile.mktemp() returns a name without creating the file.",
        "secret": "A value that looks like a real credential is written in the source file; RedWall cannot know "
                  "whether it has been revoked.",
        "deser": "The call deserializes data with a format that can execute code.",
        "xxe": "The XML parser is configured to resolve external entities.",
        "other": "The rule pattern matches this line.",
    },
    "tr": {
        "tls": "`verify=False` (veya eşdeğeri) doğrudan çağrının içinde yazılı; yapılandırmaya bağlı değil, yani "
               "her çalışmada sertifika kontrolü atlanır.",
        "debug": "debug=True sabit olarak veriliyor; RedWall bu satırın yalnızca geliştirmede çalışıp çalışmadığını "
                 "göremez.",
        "cookie": "Çerez bu çağrıda secure=True olmadan (veya secure=False ile) ayarlanıyor.",
        "weakrand": "`random` modülü, çevredeki isimlerin güvenlik değeri (token, parola, anahtar ...) "
                    "üretildiğini gösterdiği bir yerde kullanılıyor.",
        "weakhash": "MD5/SHA-1 usedforsecurity=False olmadan çağrılıyor; RedWall kullanımın güvenlikle ilgisiz "
                    "olduğunu anlayamıyor.",
        "tempfile": "tempfile.mktemp() dosyayı oluşturmadan yalnızca bir isim döndürür.",
        "secret": "Gerçek bir kimlik bilgisine benzeyen bir değer kaynak dosyaya yazılmış; RedWall bunun iptal "
                  "edilip edilmediğini bilemez.",
        "deser": "Çağrı, kod çalıştırabilen bir formatla veri çözüyor.",
        "xxe": "XML ayrıştırıcı dış varlıkları çözecek şekilde ayarlanmış.",
        "other": "Kural kalıbı bu satırla eşleşiyor.",
    },
}

_S = {
    "en": {
        "traced": "User input enters at line {src_line} via {source} and reaches `{sink}` at line {line}"
                  " ({hops} step{s} in the trace).",
        "built": "`{sink}` at line {line} receives a string built from non-constant parts; RedWall could not "
                 "prove those parts are constant.",
        "unknown": "`{sink}` at line {line} receives a value whose origin RedWall cannot see (a parameter, "
                   "attribute or call result); it stays open because it cannot be proven constant.",
        "checked_none": "RedWall looks for {mitigations}; none of them is on this path.",
        "checked_unknown": "RedWall recognises {mitigations}; none was found where this value is used, but checks "
                           "made where the value is created are not visible here.",
        "partial": "Line {line}: {what} protects only against {kinds}; this sink needs protection against {need}.",
        "limits_high": "If the value is validated outside this function (decorator, form class, middleware), "
                       "record that with `# redwall: ignore[{rule}]` and a reason; the finding will then be "
                       "listed as suppressed.",
        "limits_low": "The analysis covers this function and summaries of helpers in the scanned files; callers, "
                      "decorators, middleware and form classes are not followed yet.",
        "route_note": "The function is an HTTP route handler, so its arguments come from the request.",
        "nonprod": "The file looks like test, example or documentation code; it is ranked lower but stays in the "
                   "list because such code is sometimes deployed or copied.",
        "status": "Status `{status}`: no reviewer, LLM or proof step has confirmed or dismissed it, and there is no "
                  "`redwall: ignore` marker on the line, so it is still open.",
        "status_suppressed": "Status `suppressed`: a `redwall: ignore` marker accepts it on line {line}. It is listed "
                             "so the decision stays visible and reviewable.",
        "source_unknown": "an unnamed source",
    },
    "tr": {
        "traced": "Kullanıcı girdisi {src_line}. satırda {source} ile giriyor ve {line}. satırda `{sink}` çağrısına "
                  "ulaşıyor (izde {hops} adım).",
        "built": "{line}. satırdaki `{sink}` sabit olmayan parçalardan kurulmuş bir metin alıyor; RedWall bu "
                 "parçaların sabit olduğunu kanıtlayamadı.",
        "unknown": "{line}. satırdaki `{sink}` kaynağını RedWall'un göremediği bir değer alıyor (parametre, nitelik "
                   "veya çağrı sonucu); sabit olduğu kanıtlanamadığı için açık kalıyor.",
        "checked_none": "RedWall şunları arar: {mitigations}. Bu yolda hiçbiri yok.",
        "checked_unknown": "RedWall şunları tanır: {mitigations}. Değerin kullanıldığı yerde hiçbiri bulunmadı, ama "
                           "değerin üretildiği yerde yapılan kontroller buradan görünmüyor.",
        "partial": "{line}. satır: {what} yalnızca {kinds} için koruma sağlıyor; bu sink {need} için koruma "
                   "istiyor.",
        "limits_high": "Değer bu fonksiyonun dışında doğrulanıyorsa (dekoratör, form sınıfı, ara katman) bunu "
                       "gerekçesiyle `# redwall: ignore[{rule}]` olarak kaydedin; bulgu o zaman susturulmuş olarak "
                       "listelenir.",
        "limits_low": "Analiz bu fonksiyonu ve taranan dosyalardaki yardımcıların özetlerini kapsar; çağıranlar, "
                      "dekoratörler, ara katmanlar ve form sınıfları henüz izlenmiyor.",
        "route_note": "Fonksiyon bir HTTP rota fonksiyonu, yani argümanları istekten geliyor.",
        "nonprod": "Dosya test, örnek veya doküman koduna benziyor; daha aşağıda sıralandı ama bu tür kod bazen "
                   "yayına alındığı veya kopyalandığı için listede kalıyor.",
        "status": "Durum `{status}`: hiçbir inceleyici, LLM veya kanıt adımı onu doğrulamadı ya da reddetmedi ve "
                  "satırda `redwall: ignore` işareti yok; bu yüzden hâlâ açık.",
        "status_suppressed": "Durum `suppressed`: {line}. satırdaki `redwall: ignore` işareti onu kabul ediyor. "
                             "Karar görünür ve denetlenebilir kalsın diye listeleniyor.",
        "source_unknown": "adı bilinmeyen bir kaynak",
    },
}

_ESCAPED = re.compile(r"escaped by `(?P<what>[^`]+)` \(safe for (?P<kinds>[^)]+) only\)")
_SOURCE = re.compile(r"(`[^`]+`)")


def _lang(lang: str) -> str:
    return lang if lang in LANGS else "en"


def factor_texts(s: Score, f: Finding, lang: str) -> List[ScoreFactor]:
    lang = _lang(lang)
    out = []
    for fac in s.factors:
        if fac.key == "impact":
            text = _IMPACT[lang].get(fac.reason, _IMPACT[lang]["other"])
        elif fac.key == "evidence":
            text = _EVIDENCE[lang][("flow" if fac.reason in ("traced", "built", "unknown") else "plain", fac.reason)]
        elif fac.key == "exposure":
            text = _EXPOSURE[lang][fac.reason]
        elif fac.key == "context":
            text = _CONTEXT[lang]
        else:
            text = fac.reason
        out.append(ScoreFactor(fac.key, fac.points, text))
    return out


def why_open(f: Finding, s: Score, lang: str) -> List[str]:
    lang = _lang(lang)
    t = _S[lang]
    sink = str(f.context.get("sink") or f.snippet or f.rule_id)
    lines: List[str] = []

    flow = f.context.get("flow")
    if s.kind in DATAFLOW_KINDS and f.trace and f.confidence is Confidence.HIGH:
        first = f.trace[0]
        m = _SOURCE.search(first.note)
        source = m.group(1) if m else t["source_unknown"]
        hops = len(f.trace)
        lines.append(t["traced"].format(src_line=first.line, source=source, sink=sink, line=f.line,
                                        hops=hops, s="" if hops == 1 else "s"))
        if s.kind in _MITIGATIONS[lang]:
            lines.append(t["checked_none"].format(mitigations=_MITIGATIONS[lang][s.kind]))
    elif s.kind in DATAFLOW_KINDS and flow in ("built", "unknown") and s.kind not in ("deser", "xxe"):
        lines.append(t["built" if flow == "built" else "unknown"].format(sink=sink, line=f.line))
        if s.kind in _MITIGATIONS[lang]:
            lines.append(t["checked_unknown"].format(mitigations=_MITIGATIONS[lang][s.kind]))
    else:
        lines.append(_NON_FLOW[lang].get(s.kind, _NON_FLOW[lang]["other"]) + f" ({f.message})")

    for step in f.trace:
        m = _ESCAPED.search(step.note)
        if m:
            lines.append(t["partial"].format(line=step.line, what=f"`{m.group('what')}`",
                                             kinds=m.group("kinds"), need=s.kind))

    if s.kind in DATAFLOW_KINDS:
        if f.context.get("in_route") and s.exposure not in (REMOTE, LOCAL):
            lines.append(t["route_note"])
        lines.append(t["limits_high" if f.confidence is Confidence.HIGH else "limits_low"].format(rule=f.rule_id))
    if s.non_production:
        lines.append(t["nonprod"])
    if f.status.value == "suppressed":
        lines.append(t["status_suppressed"].format(line=f.line))
    else:
        lines.append(t["status"].format(status=f.status.value))
    return lines


def remediation_for(rule_remediation: Dict[str, str], f: Finding) -> str:
    return rule_remediation.get(f.rule_id, "")
