"""Fake website and malicious URL detection with trusted-domain awareness."""

import re
import socket
from typing import Any
from urllib.parse import urlparse

from src.utils.helpers import normalize_domain
from .domain_trust import (
    check_brand_typosquat,
    check_edit_distance_typosquat,
    is_known_legitimate,
    is_suspicious_tld,
    is_trusted_tld,
)
from .rules import DetectionResult


class URLPhishingDetector:
    """
    Detects fake/phishing websites using layered analysis:
    1. Known legitimate domains (.com, .io, etc.) → safe
    2. Strong signals (typosquat, homograph, IP URLs) → phishing
    3. Weak signals only count when combined with strong ones
    """

    STRONG_WEIGHTS = {
        "brand_typosquat": 0.55,
        "edit_distance_typosquat": 0.50,
        "homograph_attack": 0.55,
        "ip_address_url": 0.45,
        "at_symbol_redirect": 0.50,
        "suspicious_tld_with_keywords": 0.50,
    }

    WEAK_WEIGHTS = {
        "suspicious_tld": 0.15,
        "missing_https": 0.05,
        "suspicious_keywords": 0.10,
        "excessive_subdomains": 0.10,
        "long_url": 0.05,
    }

    SUSPICIOUS_URL_KEYWORDS = [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "auth",
        "wallet", "payment", "invoice", "claim", "prize",
    ]

    HOMOGRAPH_CHARS = {"а", "е", "о", "р", "с", "у", "х", "і", "ϲ"}

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        url_cfg = self.config.get("detection", {}).get("url", {})
        self.threshold = url_cfg.get("phishing_threshold", 0.45)
        self.legitimate_domains = [
            normalize_domain(d) for d in url_cfg.get("legitimate_domains", [])
        ]

    def analyze(self, url: str) -> DetectionResult:
        """Analyze a URL — legitimate .com/.io/.in/.ai sites are not flagged by default."""
        if not url.strip():
            return self._result(False, 0.0, [], {"note": "Empty URL"})

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        domain = normalize_domain(parsed.netloc.split(":")[0])
        url_lower = url.lower()

        details: dict[str, Any] = {
            "domain": domain,
            "tld": domain.rsplit(".", 1)[-1] if "." in domain else "",
            "trusted_tld": is_trusted_tld(domain),
        }

        # --- Layer 1: Known legitimate domain → SAFE ---
        if is_known_legitimate(domain, self.legitimate_domains):
            details["trust_reason"] = "Known legitimate domain or subdomain"
            return self._result(False, 0.05, [], details)

        strong: list[str] = []
        weak: list[str] = []

        # --- Strong signals (real phishing indicators) ---

        brand_match = check_brand_typosquat(domain)
        if brand_match:
            strong.append("brand_typosquat")
            details["mimics_brand"] = brand_match

        edit_match = check_edit_distance_typosquat(domain, self.legitimate_domains)
        if edit_match and "brand_typosquat" not in strong:
            strong.append("edit_distance_typosquat")
            details["similar_to"] = edit_match

        if self._has_homograph(domain):
            strong.append("homograph_attack")
            details["homograph_detected"] = True

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            strong.append("ip_address_url")
            details["ip_address"] = domain

        if "@" in parsed.netloc:
            strong.append("at_symbol_redirect")
            details["redirect_trick"] = True

        keyword_hits = [kw for kw in self.SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
        if keyword_hits:
            details["keyword_hits"] = keyword_hits[:5]

        if is_suspicious_tld(domain) and keyword_hits:
            strong.append("suspicious_tld_with_keywords")
            details["suspicious_tld"] = True

        # --- Weak signals (only meaningful with strong signals) ---

        if is_suspicious_tld(domain) and "suspicious_tld_with_keywords" not in strong:
            weak.append("suspicious_tld")

        if parsed.scheme == "http" and not is_trusted_tld(domain):
            weak.append("missing_https")

        if keyword_hits and "suspicious_tld_with_keywords" not in strong:
            weak.append("suspicious_keywords")

        if len(domain.split(".")) > 4:
            weak.append("excessive_subdomains")
            details["subdomain_count"] = len(domain.split(".")) - 2

        if len(url) > 180:
            weak.append("long_url")

        # DNS info only — never used alone to flag phishing
        details["dns_resolves"] = self._check_dns(domain)

        # --- Scoring ---
        strong_score = sum(self.STRONG_WEIGHTS.get(r, 0.4) for r in strong)
        weak_score = sum(self.WEAK_WEIGHTS.get(r, 0.05) for r in weak) if strong else 0

        # Trusted TLD (.com, .io, .in, .ai) without strong signals → safe
        if is_trusted_tld(domain) and not strong:
            details["trust_reason"] = f"Trusted TLD (.{details['tld']}) with no impersonation signals"
            return self._result(False, min(weak_score, 0.25), weak, details)

        total_score = min(strong_score + weak_score, 1.0)
        triggered = strong + (weak if strong else [])

        is_phishing = bool(strong) and total_score >= self.threshold

        return self._result(is_phishing, total_score, triggered, details)

    def analyze_batch(self, urls: list[str]) -> list[dict]:
        results = []
        for url in urls:
            result = self.analyze(url)
            results.append({
                "url": url,
                "is_phishing": result.is_phishing,
                "confidence": result.confidence,
                "risk_level": result.risk_level,
                "triggered_rules": result.triggered_rules,
                "details": result.details,
            })
        return results

    def _result(
        self, is_phishing: bool, score: float, rules: list[str], details: dict
    ) -> DetectionResult:
        return DetectionResult(
            is_phishing=is_phishing,
            confidence=round(score, 3),
            risk_level=DetectionResult.risk_from_score(score if is_phishing else score * 0.5),
            triggered_rules=rules,
            details=details,
        )

    def _has_homograph(self, domain: str) -> bool:
        return any(ord(c) > 127 or c in self.HOMOGRAPH_CHARS for c in domain)

    @staticmethod
    def _check_dns(domain: str) -> bool:
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False
