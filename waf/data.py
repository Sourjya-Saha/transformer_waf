"""Parse Juice Shop logs (3 formats) and normalise each request into a structural string.

Normalisation replaces only *dynamic* values (ids, tokens, dates, emails, build hashes) with
placeholders. Other values are kept verbatim (decoded + lower-cased) so injected payloads stay visible
to the model; collapsing every value to PARAM would make `q=' or 1=1` identical to `q=apple`.
"""
import re
from urllib.parse import unquote_plus, urlsplit

NGINX = re.compile(r'^\[[^\]]+\] client=(?P<ip>\S+) .*?method=(?P<m>\S+) uri="(?P<u>[^"]*)" proto=\S+ .*?'
                   r'referer="(?P<r>[^"]*)" user_agent="(?P<ua>[^"]*)"')
MANUAL = re.compile(r'^(?P<ip>\S+) - \[[^\]]+\] "(?P<m>\S+) (?P<u>\S+) [^"]*" \d+ \d+ "(?P<r>[^"]*)" "(?P<ua>[^"]*)"')
JUICE = re.compile(r'^\[[^\]]+\] IP:(?P<ip>\S+) METHOD:(?P<m>\S+) URL:(?P<u>\S+) STATUS:')
SITE_HOSTS = {"localhost", "localhost:3000", "127.0.0.1", "127.0.0.1:3000"}

_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-]{5,}$")  # mixed letters+digits: ids, sids, nonces
_VALUE_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-.=]{5,}$")  # same, but query values may contain dots or base64 padding
_BUILD_HASH = re.compile(r"-[a-z0-9_]{8}(\.(?:js|css|mjs|svg|woff2?|ttf|eot))$")        # SPA bundle names, change on every rebuild
_TIMESTAMP = re.compile(r"-\d{8,}")                                       # upload names like photo-1721152385146.jpg
_HEX_ID = re.compile(r"(?<![a-z0-9])(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{4,}(?![a-z0-9])")  # order_61ea-99054e44bc6a9c84.pdf
_UPLOAD = re.compile(r"^(/assets/public/images/uploads/)[^/]+-NUM(\.\w+)$")  # user-chosen upload names (after _TIMESTAMP)
_WS = re.compile(r"\s+")
_DATE = re.compile(r"^[a-z]{3},? [a-z]{3} \d{1,2},? \d{4}$")
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")


def decode(s):
    """Percent-decode until stable (max 3 rounds) so double-encoded payloads are exposed."""
    for _ in range(3):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    return s


def _value(v):
    v = _WS.sub(" ", decode(v))  # collapse runs but keep a leading/trailing newline visible (%0aid)
    if v == "":
        return ""
    if v.isdigit():
        return "NUM"
    if _DATE.match(v.lower()):
        return "DATE"
    if _EMAIL.match(v):
        return "EMAIL"
    if _VALUE_TOKEN.match(v):
        return "TOKEN"
    return v.lower()


def _segment(seg):
    seg = decode(seg)
    if seg.isdigit():
        return "NUM"
    if _TOKEN.match(seg):
        return "TOKEN"
    seg = _HEX_ID.sub("TOKEN", _TIMESTAMP.sub("-NUM", _BUILD_HASH.sub(r"-HASH\1", seg.lower())))
    return seg


def normalize(method, uri, ua=None, ref=None):
    path, _, query = uri.partition("?")
    out = _UPLOAD.sub(r"\1UPLOAD\2", "/".join(_segment(s) for s in path.split("/")))
    if "?" in uri:
        parts = []
        for kv in query.split("&"):
            k, eq, v = kv.partition("=")
            parts.append(_WS.sub(" ", decode(k).lower()) + (eq + _value(v) if eq else ""))
        out += "?" + "&".join(parts)
    s = f"{method.upper()} {out}"
    if ua and ua != "-":
        s += " UA=" + (re.match(r"[^/\s]*", ua.strip()).group(0).lower() or "empty")
    if ua is not None:  # headers were logged (juice_shop_logs.txt has none); a missing Referer means REF=NONE
        host = urlsplit(ref).netloc if ref not in (None, "", "-") else ""
        s += " REF=" + ("NONE" if not host else "SELF" if host in SITE_HOSTS else "EXT")
    return s


def parse_line(line):
    """Return (method, uri, ua, ref, ip) for one log line in any of the supported formats, else None."""
    line = line.rstrip("\n")
    for rx in (NGINX, MANUAL):
        m = rx.match(line)
        if m:
            return m["m"], m["u"], m["ua"], m["r"], m["ip"]
    m = JUICE.match(line)
    if m:
        u = urlsplit(m["u"])
        if u.netloc not in SITE_HOSTS:  # browser fetching a third-party CDN, not a request to the site
            return None
        return m["m"], u.path + ("?" + u.query if u.query else ""), None, None, m["ip"]
    return None


def load_logs(paths):
    """Return {normalised_request: count} over all given text log files."""
    counts = {}
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                r = parse_line(line)
                if r:
                    n = normalize(*r[:4])
                    counts[n] = counts.get(n, 0) + 1
    return counts


if __name__ == "__main__":
    assert normalize("GET", "/rest/products/search?q=apple") == "GET /rest/products/search?q=apple"
    assert normalize("GET", "/rest/basket/6", "Mozilla/5.0 (X11)", "http://localhost/basket") == \
        "GET /rest/basket/NUM UA=mozilla REF=SELF"
    assert normalize("GET", "/api/Products/52?d=Mon%20Sep%2007%202026") == "GET /api/products/NUM?d=DATE"
    assert normalize("GET", "/chunk-DBPdFzgj.js") == "GET /chunk-HASH.js"
    assert normalize("GET", "/media/no-jtvuctct.svg") == "GET /media/no-HASH.svg"
    assert normalize("GET", "/up/Photo-1721152385146.jpg") == "GET /up/photo-NUM.jpg"
    assert normalize("GET", "/s?q=%2527%2520OR%25201%253D1--") == "GET /s?q=' or 1=1--"  # double-encoded
    assert normalize("GET", "/s?q=UnIoN%0aSeLeCt") == "GET /s?q=union select"
    assert normalize("GET", "/s?q=%0aid") == "GET /s?q= id"  # leading newline must survive
    assert normalize("GET", "/", "curl/8.1", None) == "GET / UA=curl REF=NONE"  # absent Referer header
    assert normalize("GET", "/ftp/order_61ea-99054e44bc6a9c84.pdf") == "GET /ftp/order_TOKEN-TOKEN.pdf"
    assert normalize("GET", "/assets/public/images/uploads/My%20Pic!-1721152385146.jpg") == "GET /assets/public/images/uploads/UPLOAD.jpg"
    assert normalize("GET", "/media/font-mfizz-4uogiena.woff") == "GET /media/font-mfizz-HASH.woff"
    assert normalize("GET", "/socket.io/?EIO=4&t=Q34cwzl.0") == "GET /socket.io/?eio=NUM&t=TOKEN"
    assert normalize("GET", "/assets/public/images/uploads/../../../etc/passwd") == "GET /assets/public/images/uploads/../../../etc/passwd"
    assert parse_line('[2026-09-21T15:23:59.1+00:00] IP:127.0.0.1 METHOD:GET URL:http://cdn.x.com/a.js STATUS:200') is None
    print("data.py self-check ok")
