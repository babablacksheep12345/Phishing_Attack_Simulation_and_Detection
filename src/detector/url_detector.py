"""Website and malicious URL detection with trusted-domain awareness."""

import re
import socket
from typing import Any
from urllib.parse import urlparse

from src.utils.helpers import normalize_domain
from .domain_trust import (
    analyze_domain,
    is_known_legitimate,
    is_suspicious_tld,
    is_trusted_tld,
    PHISHING_PATH_KEYWORDS,
)
from .rules import DetectionResult


class URLPhishingDetector:
    """Detects phishing websites using domain analysis + URL heuristics."""

    STRONG_WEIGHTS = {
        "brand_typosquat": 0.55,
        "edit_distance_typosquat": 0.50,
        "brand_impersonation": 0.50,
        "homograph_attack": 0.55,
        "ip_address_url": 0.45,
        "at_symbol_redirect": 0.50,
        "suspicious_tld_with_keywords": 0.50,
    }

    HOMOGRAPH_CHARS = {"а", "е", "о", "р", "с", "у", "х", "і", "ϲ"}

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        url_cfg = self.config.get("detection", {}).get("url", {})
        self.threshold = url_cfg.get("phishing_threshold", 0.45)
        self.legitimate_domains = [
            normalize_domain(d) for d in url_cfg.get("legitimate_domains", [])
        ]

    def analyze(self, url: str) -> DetectionResult:
        """Analyze a URL for phishing — legitimate .com/.io/.in/.ai sites stay safe."""
        if not url.strip():
            return self._result(False, 0.0, [], {"note": "Empty URL"})

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        domain = normalize_domain(parsed.netloc.split(":")[0])
        url_lower = url.lower()
        path_and_query = (parsed.path + parsed.query).lower()

        details: dict[str, Any] = {
            "domain": domain,
            "tld": domain.rsplit(".", 1)[-1] if "." in domain else "",
            "trusted_tld": is_trusted_tld(domain),
        }

        # Known whitelist → safe
        if is_known_legitimate(domain, self.legitimate_domains):
            details["trust_reason"] = "Known legitimate domain"
            return self._result(False, 0.05, [], details)

        # Domain-level analysis (typosquat, brand impersonation, etc.)
        domain_result = analyze_domain(domain, self.legitimate_domains)
        strong: list[str] = list(domain_result["rules"])
        details.update(domain_result["details"])

        # URL-specific strong signals
        if self._has_homograph(domain):
            strong.append("homograph_attack")
            details["homograph_detected"] = True

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            strong.append("ip_address_url")
            details["ip_address"] = domain

        if "@" in parsed.netloc:
            strong.append("at_symbol_redirect")
            details["redirect_trick"] = True

        keyword_hits = [kw for kw in PHISHING_PATH_KEYWORDS if kw in url_lower]
        if keyword_hits:
            details["keyword_hits"] = keyword_hits[:5]

        if is_suspicious_tld(domain) and keyword_hits:
            if "suspicious_tld_with_keywords" not in strong:
                strong.append("suspicious_tld_with_keywords")

        # Domain already marked safe on trusted TLD
        if domain_result.get("details", {}).get("trust_reason") and not domain_result["is_phishing"]:
            if not any(r in strong for r in ("homograph_attack", "ip_address_url", "at_symbol_redirect")):
                return self._result(False, domain_result["confidence"], domain_result["rules"], details)

        # Score
        strong_score = sum(self.STRONG_WEIGHTS.get(r, 0.4) for r in strong)
        domain_score = domain_result["confidence"]
        total_score = min(max(strong_score, domain_score), 1.0)

        is_phishing = domain_result["is_phishing"] or (
            bool(strong) and total_score >= self.threshold
        )

        return self._result(is_phishing, total_score, strong, details)

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
        display_score = score if is_phishing else score * 0.4
        return DetectionResult(
            is_phishing=is_phishing,
            confidence=round(score, 3),
            risk_level=DetectionResult.risk_from_score(display_score),
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
