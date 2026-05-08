import re
import urllib.parse

def analyze_url(raw_url: str) -> dict:
    issues  = []
    checks  = []
    score   = 0

    try:
        if not raw_url.startswith("http"):
            raw_url = "http://" + raw_url
        url = urllib.parse.urlparse(raw_url)
    except Exception:
        return {"error": "Invalid URL — could not parse"}

    hostname  = url.netloc or url.path
    path      = url.path
    query     = url.query
    full      = raw_url
    query_str = urllib.parse.unquote((query + " " + path)).lower()

    # 1. HTTPS
    if url.scheme != "https":
        issues.append({"type": "bad", "cat": "Transport", "msg": "No HTTPS — data transmitted in plaintext"})
        score += 20
        checks.append({"label": "HTTPS", "status": "fail"})
    else:
        checks.append({"label": "HTTPS", "status": "pass"})

    # 2. IP-based URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", hostname):
        issues.append({"type": "bad", "cat": "Phishing", "msg": "IP-based URL — commonly used in phishing attacks"})
        score += 30
        checks.append({"label": "IP Address", "status": "fail"})
    else:
        checks.append({"label": "IP Address", "status": "pass"})

    # 3. Subdomains
    parts = hostname.split(".")
    if len(parts) - 2 > 2:
        issues.append({"type": "warn", "cat": "Phishing", "msg": f"Too many subdomains ({len(parts)-2})"})
        score += 15
        checks.append({"label": "Subdomain Count", "status": "warn"})
    else:
        checks.append({"label": "Subdomain Count", "status": "pass"})

    # 4. Fake brand keywords
    BRANDS = ["paypal","bank","amazon","apple","microsoft","google","facebook",
              "netflix","instagram","login","secure","verify","account","update",
              "confirm","ebay","signin","password","credential"]
    found_brands = [b for b in BRANDS if b in hostname.lower() or b in query_str]
    if found_brands:
        issues.append({"type": "warn", "cat": "Phishing", "msg": f"Brand keywords: {', '.join(found_brands[:5])}"})
        score += min(len(found_brands) * 10, 30)
        checks.append({"label": "Brand Spoofing", "status": "warn"})
    else:
        checks.append({"label": "Brand Spoofing", "status": "pass"})

    # 5. URL length
    if len(full) > 75:
        issues.append({"type": "warn", "cat": "Structure", "msg": f"URL too long ({len(full)} chars)"})
        score += 10
        checks.append({"label": "URL Length", "status": "warn"})
    else:
        checks.append({"label": "URL Length", "status": "pass"})

    # 6. @ symbol
    if "@" in full:
        issues.append({"type": "bad", "cat": "Obfuscation", "msg": "'@' hides real destination domain"})
        score += 20

    # 7. Multiple hyphens
    if full.count("-") > 4:
        issues.append({"type": "warn", "cat": "Structure", "msg": "Multiple hyphens — spoofed domain pattern"})
        score += 8

    # 8. Unicode
    if re.search(r"[^\x00-\x7F]", full):
        issues.append({"type": "bad", "cat": "Obfuscation", "msg": "Unicode characters — homograph attack possible"})
        score += 25

    # 9. Bad TLDs
    BAD_TLDS = [".xyz",".top",".tk",".ml",".ga",".cf",".gq",".click",".work",".loan",".pw"]
    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in BAD_TLDS:
        issues.append({"type": "warn", "cat": "Reputation", "msg": f"High-risk TLD: {tld}"})
        score += 12

    # 10. SQL Injection
    SQLI = ["' or","1=1","' --","/*","union select","drop table","insert into","exec(","waitfor delay"]
    found_sqli = [p for p in SQLI if p in query_str]
    if found_sqli:
        issues.append({"type": "bad", "cat": "SQL Injection", "msg": f"SQLi pattern: {', '.join(found_sqli[:3])}"})
        score += 30
        checks.append({"label": "SQL Injection", "status": "fail"})
    else:
        checks.append({"label": "SQL Injection", "status": "pass"})

    # 11. XSS
    XSS = ["<script","javascript:","onerror=","onload=","alert(","document.cookie","eval(","<iframe","<svg"]
    found_xss = [p for p in XSS if p in query_str]
    if found_xss:
        issues.append({"type": "bad", "cat": "XSS", "msg": f"XSS payload: {', '.join(found_xss[:3])}"})
        score += 35
        checks.append({"label": "XSS Payload", "status": "fail"})
    else:
        checks.append({"label": "XSS Payload", "status": "pass"})

    # 12. Path traversal
    if "../" in full or "..%2F" in full.lower():
        issues.append({"type": "bad", "cat": "Path Traversal", "msg": "Directory traversal detected (../)"})
        score += 25
        checks.append({"label": "Path Traversal", "status": "fail"})
    else:
        checks.append({"label": "Path Traversal", "status": "pass"})

    # 13. Open redirect
    if re.search(r"(redirect|url|next|goto|return)=https?://", query_str):
        issues.append({"type": "warn", "cat": "Open Redirect", "msg": "Open redirect parameter detected"})
        score += 15

    # 14. Bad port
    if url.port and url.port not in (80, 443, 8080, 8443):
        issues.append({"type": "warn", "cat": "Structure", "msg": f"Non-standard port: {url.port}"})
        score += 10

    score = min(score, 100)

    if score >= 70:
        recs = ["Do NOT visit this URL.", "Report to IT/security team immediately.",
                "Never enter credentials here.", "Block this domain at firewall level."]
    elif score >= 40:
        recs = ["Proceed with extreme caution.", "Avoid entering sensitive info.",
                "Verify through official channels.", "Use VPN for investigation."]
    else:
        recs = ["URL appears relatively safe.", "Exercise standard browsing hygiene.",
                "Keep browser and antivirus updated."]

    return {
        "url": raw_url, "hostname": hostname, "protocol": url.scheme,
        "path": path, "query": query, "score": score,
        "issues": issues, "checks": checks, "recommendations": recs,
    }