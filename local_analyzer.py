import re

def analyze_url(url):
    risk_score = 0

    # SQL Injection patterns
    if re.search(r"or 1=1|--", url):
        risk_score += 30

    # XSS patterns
    if re.search(r"<script>|alert\(", url):
        risk_score += 30

    # Phishing keywords
    if any(word in url for word in ["login", "verify", "bank"]):
        risk_score += 20

    return risk_score


# Test URL
test_url = "http://example.com/login?id=1' OR 1=1--"

score = analyze_url(test_url)

print("URL:", test_url)
print("Risk Score:", score, "/100")
