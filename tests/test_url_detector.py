"""Tests for URL phishing detector."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector.url_detector import URLPhishingDetector
from src.utils.helpers import load_config


def test_detects_typosquat_url():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("http://paypa1-secure.com/login")
    assert result.is_phishing is True
    assert result.confidence >= 0.45


def test_detects_microsft_typosquat():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("http://microsft-login.com/signin")
    assert result.is_phishing is True


def test_detects_windows_impersonation():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("http://windows-security-alert.com/download/patch")
    assert result.is_phishing is True


def test_legitimate_github_safe():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("https://www.github.com/login")
    assert result.is_phishing is False


def test_legitimate_com_domain_safe():
    detector = URLPhishingDetector(load_config())
    for url in [
        "https://www.google.com",
        "https://stackoverflow.com/questions",
        "https://codectechnologies.in",
    ]:
        result = detector.analyze(url)
        assert result.is_phishing is False, f"False positive on {url}"


def test_legitimate_io_in_ai_tlds_safe():
    detector = URLPhishingDetector(load_config())
    for url in [
        "https://example.io/dashboard",
        "https://startup.in/about",
        "https://myapp.ai/login",
    ]:
        result = detector.analyze(url)
        assert result.is_phishing is False, f"False positive on {url}"


def test_suspicious_tld_with_keywords():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("http://fake-login.xyz/verify")
    assert result.is_phishing is True


def test_ip_address_url():
    detector = URLPhishingDetector(load_config())
    result = detector.analyze("http://192.168.1.1/login")
    assert result.is_phishing is True
    assert "ip_address_url" in result.triggered_rules
