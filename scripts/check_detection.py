"""Quick detection accuracy check."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector.email_detector import EmailPhishingDetector
from src.detector.url_detector import URLPhishingDetector
from src.simulator.email_simulator import EmailSimulator
from src.utils.helpers import load_config

config = load_config()
url_d = URLPhishingDetector(config)
email_d = EmailPhishingDetector(config)
sim = EmailSimulator()

print("=== PHISHING URLs (should detect) ===")
phish = [
    "http://paypa1-secure.com/login",
    "http://microsft-login.com/signin",
    "http://g00gle-security.com/auth",
    "http://secure-banking-update.xyz/verify",
    "http://amaz0n-billing.net/invoice",
    "http://quickb00ks-online.com/billing",
    "http://payroll-services.xyz/payment/invoice",
    "http://secure-login-verify.xyz/account/update",
    "http://192.168.1.100/login",
    "http://netfl1x-billing.com/reactivate",
    "http://support@evil.com@paypa1-secure.com/login",
]
miss = 0
for u in phish:
    r = url_d.analyze(u)
    if not r.is_phishing:
        miss += 1
    status = "OK" if r.is_phishing else "MISS"
    print(f"{status} {r.confidence:.2f} {u}")
    print(f"     rules: {r.triggered_rules}")

print(f"\nMissed: {miss}/{len(phish)}")

print("\n=== LEGITIMATE URLs (should NOT detect) ===")
legit = [
    "https://www.github.com/login",
    "https://www.google.com",
    "https://www.paypal.com/signin",
    "https://codectechnologies.in",
    "https://stackoverflow.com",
    "https://myapp.io/login",
    "https://startup.ai/dashboard",
    "https://amazonaws.com/s3",
]
fp = 0
for u in legit:
    r = url_d.analyze(u)
    if r.is_phishing:
        fp += 1
    status = "OK" if not r.is_phishing else "FALSE+"
    print(f"{status} {r.confidence:.2f} {u} | {r.triggered_rules}")

print(f"\nFalse positives: {fp}/{len(legit)}")

print("\n=== SIMULATED EMAILS ===")
emails = sim.simulate_campaign(5)
email_miss = 0
for email_data in emails:
    r = email_d.analyze_email_dict(email_data["email"])
    if not r.is_phishing:
        email_miss += 1
    status = "OK" if r.is_phishing else "MISS"
    subj = email_data["email"]["subject"][:40]
    print(f"{status} {r.confidence:.2f} {email_data['scenario']} | {subj}")

print(f"\nEmail missed: {email_miss}/{len(emails)}")
