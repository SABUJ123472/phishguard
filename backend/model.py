import re
import math
import tldextract
import numpy as np
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "credential", "paypal", "amazon", "google",
    "apple", "microsoft", "netflix", "ebay", "wellsfargo", "chase"
]

COMMON_BRANDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "ebay", "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "wellsfargo", "chase", "bankofamerica", "citibank"
]

def entropy(s):
    if not s:
        return 0
    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq)

def levenshtein(a, b):
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            dp[j] = prev[j - 1] if a[i-1] == b[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]

def brand_similarity(domain):
    domain_clean = re.sub(r'[^a-z0-9]', '', domain.lower())
    for brand in COMMON_BRANDS:
        if brand in domain_clean:
            return 0
        dist = levenshtein(domain_clean, brand)
        if dist <= 2 and abs(len(domain_clean) - len(brand)) <= 3:
            return 1
    return 0

def extract_features(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        ext = tldextract.extract(url)
        domain = ext.domain
        full_domain = f"{ext.domain}.{ext.suffix}"
        path = parsed.path
        hostname = parsed.hostname or ""

        features = {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_at": url.count("@"),
            "num_slash": url.count("/"),
            "num_question": url.count("?"),
            "num_equal": url.count("="),
            "num_ampersand": url.count("&"),
            "num_percent": url.count("%"),
            "num_digits_in_domain": sum(c.isdigit() for c in domain),
            "has_ip": 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
            "has_https": 1 if parsed.scheme == "https" else 0,
            "has_suspicious_keyword": int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)),
            "subdomain_count": len(ext.subdomain.split(".")) if ext.subdomain else 0,
            "path_length": len(path),
            "entropy_domain": entropy(domain),
            "brand_similarity": brand_similarity(domain),
            "double_slash_redirect": 1 if url.count("//") > 1 else 0,
            "prefix_suffix_hyphen": 1 if "-" in domain else 0,
        }
        return features
    except Exception:
        return None

def features_to_array(features):
    keys = [
        "url_length", "domain_length", "num_dots", "num_hyphens", "num_at",
        "num_slash", "num_question", "num_equal", "num_ampersand", "num_percent",
        "num_digits_in_domain", "has_ip", "has_https", "has_suspicious_keyword",
        "subdomain_count", "path_length", "entropy_domain", "brand_similarity",
        "double_slash_redirect", "prefix_suffix_hyphen"
    ]
    return np.array([features[k] for k in keys], dtype=float)

def get_suspicious_reasons(features):
    reasons = []
    if features["brand_similarity"]:
        reasons.append("Domain similarity to known brand detected")
    if features["has_ip"]:
        reasons.append("IP address used instead of domain name")
    if not features["has_https"]:
        reasons.append("No SSL/HTTPS encryption")
    if features["has_suspicious_keyword"]:
        reasons.append("Suspicious keywords found in URL")
    if features["num_at"] > 0:
        reasons.append("'@' symbol detected in URL")
    if features["double_slash_redirect"]:
        reasons.append("Suspicious redirect pattern detected")
    if features["url_length"] > 75:
        reasons.append("Unusually long URL")
    if features["num_hyphens"] > 3:
        reasons.append("Excessive hyphens in domain")
    if features["num_dots"] > 4:
        reasons.append("Excessive dots (possible subdomain abuse)")
    if features["subdomain_count"] > 2:
        reasons.append("Multiple subdomains detected")
    if features["prefix_suffix_hyphen"]:
        reasons.append("Hyphen in domain name (common phishing tactic)")
    if features["entropy_domain"] > 3.5:
        reasons.append("High domain entropy (randomized domain)")
    return reasons
