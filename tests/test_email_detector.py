"""Tests for email phishing detector."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector.email_detector import EmailPhishingDetector
from src.utils.helpers import load_config


def test_detects_phishing_email():
    config = load_config()
    detector = EmailPhishingDetector(config)

    result = detector.analyze(
        subject="URGENT: Verify Your Account Immediately",
        body="Dear User,\n\nYour account will be suspended. Click here: http://paypa1-secure.com/verify\n\nAct now!",
        from_address="security@paypa1-secure.com",
        from_display="PayPal Security",
    )

    assert result.is_phishing is True
    assert result.confidence >= 0.5
    assert len(result.triggered_rules) > 0


def test_legitimate_email_not_flagged():
    config = load_config()
    detector = EmailPhishingDetector(config)

    result = detector.analyze(
        subject="Your order has shipped",
        body="Hi Shikha,\n\nYour order #12345 has shipped.\n\nTrack: https://www.amazon.com/gp/css/shiptrack\n\nThanks, Amazon",
        from_address="shipment-tracking@amazon.com",
        from_display="Amazon",
    )

    assert result.is_phishing is False


def test_urgency_detection():
    config = load_config()
    detector = EmailPhishingDetector(config)

    result = detector.analyze(
        subject="Act now - limited time offer",
        body="Click immediately to claim your prize.",
        from_address="promo@suspicious.xyz",
    )

    assert "urgency_keywords" in result.triggered_rules
