"""
Security Log Analyzer
----------------------
Parses SSH authentication logs (in the standard /var/log/auth.log style
format) and flags suspicious activity: repeated failed logins from the
same IP (possible brute-force attempts) and login attempts against
common/invalid usernames.

Usage:
    python log_analyzer.py sample_auth.log
"""

import re
import argparse
from collections import defaultdict, Counter

# Regex patterns for the two log lines we care about.
FAILED_LOGIN_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2"
)
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2"
)

# If one IP fails this many times or more, we flag it as a possible
# brute-force attempt.
BRUTE_FORCE_THRESHOLD = 4


def analyze_log(filepath: str):
    failed_by_ip = defaultdict(int)
    failed_users = Counter()
    accepted_logins = []

    with open(filepath, "r") as f:
        for line in f:
            fail_match = FAILED_LOGIN_RE.search(line)
            if fail_match:
                ip = fail_match.group("ip")
                user = fail_match.group("user")
                failed_by_ip[ip] += 1
                failed_users[user] += 1
                continue

            ok_match = ACCEPTED_LOGIN_RE.search(line)
            if ok_match:
                accepted_logins.append((ok_match.group("user"), ok_match.group("ip")))

    return failed_by_ip, failed_users, accepted_logins


def print_report(failed_by_ip, failed_users, accepted_logins):
    print("=" * 55)
    print(" SECURITY LOG ANALYSIS REPORT")
    print("=" * 55)

    print(f"\nTotal successful logins: {len(accepted_logins)}")
    for user, ip in accepted_logins:
        print(f"  - {user} logged in from {ip}")

    print(f"\nTotal distinct IPs with failed logins: {len(failed_by_ip)}")

    print("\n--- Suspicious IPs (possible brute-force) ---")
    flagged = False
    for ip, count in sorted(failed_by_ip.items(), key=lambda x: -x[1]):
        if count >= BRUTE_FORCE_THRESHOLD:
            flagged = True
            print(f"  [ALERT] {ip} — {count} failed attempts")
        else:
            print(f"  {ip} — {count} failed attempt(s)")
    if not flagged:
        print("  No IP crossed the brute-force threshold.")

    print("\n--- Most targeted usernames ---")
    for user, count in failed_users.most_common(5):
        print(f"  {user}: {count} attempt(s)")

    print("\n" + "=" * 55)


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH auth logs for suspicious activity.")
    parser.add_argument("logfile", help="Path to the auth log file")
    args = parser.parse_args()

    failed_by_ip, failed_users, accepted_logins = analyze_log(args.logfile)
    print_report(failed_by_ip, failed_users, accepted_logins)


if __name__ == "__main__":
    main()
