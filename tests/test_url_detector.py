"""Tests for URL phishing detector."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector.url_detector import URLPhishingDetector
from src.utils.helpers import load_config


def test_detects_typosquat_url():
    config = load_config()
    detector = URLPhishingDetector(config)

    result = detector.analyze("http://paypa1-secure.com/login")

    assert result.is_phishing is True
    assert "typosquatting" in result.triggered_rules or "suspicious_keywords_in_url" in result.triggered_rules


def test_legitimate_url_safe():
    config = load_config()
    detector = URLPhishingDetector(config)

    result = detector.analyze("https://www.github.com/login")

    assert result.is_phishing is False


def test_suspicious_tld():
    config = load_config()
    detector = URLPhishingDetector(config)

    result = detector.analyze("http://fake-login.xyz/verify")

    assert result.is_phishing is True
    assert "suspicious_tld" in result.triggered_rules


def test_ip_address_url():
    config = load_config()
    detector = URLPhishingDetector(config)

    result = detector.analyze("http://192.168.1.1/login")

    assert "ip_address_url" in result.triggered_rules
