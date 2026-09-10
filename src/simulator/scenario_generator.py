"""Phishing scenario templates for security awareness training."""

import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhishingScenario:
    """A simulated phishing attack scenario."""

    name: str
    category: str
    subject: str
    sender_display: str
    sender_email: str
    body: str
    malicious_url: str
    red_flags: list[str] = field(default_factory=list)
    difficulty: str = "medium"


class ScenarioGenerator:
    """Generates phishing email scenarios for awareness training."""

    SCENARIOS: dict[str, dict[str, Any]] = {
        "credential_harvest": {
            "name": "Credential Harvesting",
            "category": "credential_harvest",
            "subjects": [
                "Action Required: Verify Your Account Immediately",
                "Your Password Will Expire in 24 Hours",
                "Security Alert: Unusual Sign-in Detected",
            ],
            "senders": [
                ("IT Security Team", "security-noreply@it-support-verify.com"),
                ("Microsoft Account Team", "account@microsft-login.com"),
                ("Google Security", "alerts@g00gle-security.com"),
            ],
            "body_template": """Dear User,

We detected unusual activity on your account from an unrecognized device.

To protect your account, you must verify your identity within 24 hours.
Failure to verify will result in account suspension.

Verify now: {url}

If you did not request this, please ignore this email.

Best regards,
Security Team""",
            "urls": [
                "http://secure-login-verify.xyz/account/update",
                "http://microsft-login.com/signin/verify",
                "http://g00gle-security.com/auth/confirm",
            ],
            "red_flags": [
                "Urgency and threat of account suspension",
                "Spoofed sender domain (typosquatting)",
                "Generic greeting ('Dear User')",
                "Suspicious URL not matching official domain",
            ],
        },
        "fake_invoice": {
            "name": "Fake Invoice Scam",
            "category": "fake_invoice",
            "subjects": [
                "Invoice #INV-2024-8847 - Payment Overdue",
                "Your Amazon Order Invoice - Action Required",
                "Pending Payment: Invoice Attached",
            ],
            "senders": [
                ("Accounts Payable", "billing@amaz0n-billing.net"),
                ("Finance Department", "invoices@payroll-services.xyz"),
                ("QuickBooks", "noreply@quickb00ks-online.com"),
            ],
            "body_template": """Hello,

Please find attached your invoice for recent services.

Amount Due: $847.50
Due Date: Immediate

View and pay invoice: {url}

Thank you for your prompt attention.

Accounts Receivable""",
            "urls": [
                "http://amaz0n-billing.net/invoice/view/8847",
                "http://payroll-services.xyz/payment/invoice",
                "http://quickb00ks-online.com/billing/pay",
            ],
            "red_flags": [
                "Unexpected invoice with no prior context",
                "Pressure for immediate payment",
                "Domain mimics legitimate brand with typos",
                "No legitimate company contact information",
            ],
        },
        "account_suspension": {
            "name": "Account Suspension Threat",
            "category": "account_suspension",
            "subjects": [
                "URGENT: Your Account Has Been Suspended",
                "Final Notice: Account Termination in 48 Hours",
                "Immediate Action Required - Account Locked",
            ],
            "senders": [
                ("PayPal Security", "security@paypa1-secure.com"),
                ("Netflix Support", "support@netfl1x-billing.com"),
                ("Bank Alert", "alerts@secure-banking-update.xyz"),
            ],
            "body_template": """IMPORTANT SECURITY NOTICE

Your account has been temporarily suspended due to suspicious activity.

To restore access, confirm your identity immediately:
{url}

This is your final notice. Unverified accounts will be permanently closed.

Support Team""",
            "urls": [
                "http://paypa1-secure.com/restore/account",
                "http://netfl1x-billing.com/reactivate",
                "http://secure-banking-update.xyz/verify/identity",
            ],
            "red_flags": [
                "ALL CAPS urgency in subject line",
                "Threat of permanent account closure",
                "Character substitution in domain (1 for l, 0 for o)",
                "No personalized account details",
            ],
        },
        "prize_scam": {
            "name": "Prize/Lottery Scam",
            "category": "prize_scam",
            "subjects": [
                "Congratulations! You've Won $50,000!",
                "You Are Our Lucky Winner - Claim Your Prize",
                "FREE iPhone 15 - Limited Time Offer",
            ],
            "senders": [
                ("Prize Notification", "winner@global-prize-center.xyz"),
                ("Apple Promotions", "promo@app1e-giveaway.com"),
                ("Lucky Draw Team", "claim@instant-rewards.club"),
            ],
            "body_template": """CONGRATULATIONS!

You have been selected as a winner in our exclusive promotion!

Prize: $50,000 Cash + iPhone 15 Pro

Claim your prize before it expires: {url}

Act now - this offer expires in 24 hours!

Promotions Department""",
            "urls": [
                "http://global-prize-center.xyz/claim/prize",
                "http://app1e-giveaway.com/redeem/free",
                "http://instant-rewards.club/winner/claim",
            ],
            "red_flags": [
                "Too-good-to-be-true offer",
                "You didn't enter any contest",
                "Requires clicking link to 'claim' prize",
                "Suspicious TLD (.xyz, .club)",
            ],
        },
        "tech_support": {
            "name": "Fake Tech Support",
            "category": "tech_support",
            "subjects": [
                "Critical: Your Computer Is Infected",
                "Windows Security Alert - Virus Detected",
                "Your License Has Expired - Renew Now",
            ],
            "senders": [
                ("Windows Defender", "alert@windows-security-alert.com"),
                ("Microsoft Support", "help@microsoft-helpdesk.xyz"),
                ("System Administrator", "admin@it-helpdesk-support.net"),
            ],
            "body_template": """CRITICAL SECURITY ALERT

Our systems detected {count} viruses on your device.

Your personal data may be at risk. Immediate action is required.

Download security patch: {url}

Or call our support line: 1-800-FAKE-NUM

Do not ignore this message.

Windows Security Team""",
            "urls": [
                "http://windows-security-alert.com/download/patch",
                "http://microsoft-helpdesk.xyz/fix/virus",
                "http://it-helpdesk-support.net/remote/assist",
            ],
            "red_flags": [
                "Unsolicited virus warning",
                "Requests downloading unknown software",
                "Fake support phone number",
                "Creates fear to bypass rational thinking",
            ],
        },
    }

    def list_scenarios(self) -> list[str]:
        """Return available scenario keys."""
        return list(self.SCENARIOS.keys())

    def generate(self, scenario_key: str | None = None) -> PhishingScenario:
        """Generate a random or specific phishing scenario."""
        key = scenario_key or random.choice(list(self.SCENARIOS.keys()))
        if key not in self.SCENARIOS:
            raise ValueError(f"Unknown scenario: {key}. Available: {self.list_scenarios()}")

        template = self.SCENARIOS[key]
        idx = random.randint(0, len(template["subjects"]) - 1)

        sender_display, sender_email = template["senders"][idx % len(template["senders"])]
        url = template["urls"][idx % len(template["urls"])]
        body = template["body_template"].format(url=url, count=random.randint(3, 12))

        return PhishingScenario(
            name=template["name"],
            category=template["category"],
            subject=template["subjects"][idx],
            sender_display=sender_display,
            sender_email=sender_email,
            body=body,
            malicious_url=url,
            red_flags=template["red_flags"],
            difficulty=random.choice(["easy", "medium", "hard"]),
        )

    def generate_batch(self, count: int = 5) -> list[PhishingScenario]:
        """Generate multiple scenarios for a training session."""
        keys = list(self.SCENARIOS.keys())
        return [self.generate(keys[i % len(keys)]) for i in range(count)]
