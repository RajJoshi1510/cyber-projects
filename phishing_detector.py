"""
Phishing URL Risk Analyzer
----------------------------
A rule-based tool that inspects a URL for common characteristics of
phishing links (no external ML dataset needed, so it's easy to run and
easy to explain in an interview). Each rule adds points to a risk score;
the total score maps to Low / Medium / High risk.

Usage:
    python phishing_detector.py "http://192.168.1.5-login-verify.com/account"
"""

import re
import argparse
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "webscr", "paypal", "password",
]


def has_ip_address(hostname: str) -> bool:
    """Phishing URLs sometimes use a raw IP address instead of a domain name."""
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return bool(ip_pattern.match(hostname))


def analyze_url(url: str):
    score = 0
    reasons = []

    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    # Rule 1: URL length
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long (>75 chars)")

    # Rule 2: Uses IP address instead of a domain name
    if has_ip_address(hostname):
        score += 3
        reasons.append("Hostname is a raw IP address")

    # Rule 3: No HTTPS
    if parsed.scheme != "https":
        score += 1
        reasons.append("Does not use HTTPS")

    # Rule 4: '@' symbol in URL (used to obscure the real destination)
    if "@" in url:
        score += 3
        reasons.append("Contains '@' symbol (can hide the real destination)")

    # Rule 5: Excessive hyphens in the domain (typosquatting pattern)
    if hostname.count("-") >= 2:
        score += 1
        reasons.append("Domain contains multiple hyphens")

    # Rule 6: Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if found_keywords:
        score += len(found_keywords)
        reasons.append(f"Contains suspicious keyword(s): {', '.join(found_keywords)}")

    # Rule 7: Many subdomains (e.g. login.secure.bank.example.co.something.com)
    subdomain_count = hostname.count(".")
    if subdomain_count > 3:
        score += 2
        reasons.append("Unusually high number of subdomains")

    # Map score to a risk level
    if score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, score, reasons


def main():
    parser = argparse.ArgumentParser(description="Rule-based phishing URL risk analyzer.")
    parser.add_argument("url", help="The URL to analyze")
    args = parser.parse_args()

    risk, score, reasons = analyze_url(args.url)

    print(f"\nURL: {args.url}")
    print(f"Risk Level: {risk}  (score: {score})")
    if reasons:
        print("Indicators found:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("No suspicious indicators found.")
    print()


if __name__ == "__main__":
    main()
