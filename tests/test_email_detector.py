"""Tests for email phishing detector."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector.email_detector import EmailPhishingDetector
from src.simulator.scenario_generator import ScenarioGenerator
from src.utils.helpers import load_config


def test_detects_phishing_email():
    detector = EmailPhishingDetector(load_config())
    result = detector.analyze(
        subject="URGENT: Verify Your Account Immediately",
        body="Dear User,\n\nYour account will be suspended. Click here: http://paypa1-secure.com/verify\n\nAct now!",
        from_address="security@paypa1-secure.com",
        from_display="PayPal Security",
    )
    assert result.is_phishing is True
    assert result.confidence >= 0.45


def test_legitimate_email_not_flagged():
    detector = EmailPhishingDetector(load_config())
    result = detector.analyze(
        subject="Your order has shipped",
        body="Hi Shikha,\n\nYour order #12345 has shipped.\n\nTrack: https://www.amazon.com/gp/css/shiptrack\n\nThanks, Amazon",
        from_address="shipment-tracking@amazon.com",
        from_display="Amazon",
    )
    assert result.is_phishing is False


def test_all_simulated_scenarios_detected():
    detector = EmailPhishingDetector(load_config())
    gen = ScenarioGenerator()
    for key in gen.list_scenarios():
        scenario = gen.generate(key)
        result = detector.analyze(
            scenario.subject, scenario.body, scenario.sender_email, scenario.sender_display
        )
        assert result.is_phishing is True, f"Missed scenario: {key} (score={result.confidence})"
