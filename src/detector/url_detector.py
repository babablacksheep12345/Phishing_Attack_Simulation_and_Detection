"""Fake website and malicious URL detection."""

import re
import socket
from typing import Any
from urllib.parse import urlparse

from src.utils.helpers import levenshtein_distance, normalize_domain
from .rules import DetectionResult, score_from_rules


class URLPhishingDetector:
    """Detects fake/phishing websites through URL analysis."""

    RULE_WEIGHTS = {
        "typosquatting": 0.30,
        "suspicious_tld": 0.20,
        "ip_address_url": 0.25,
        "excessive_subdomains": 0.15,
        "homograph_attack": 0.25,
        "missing_https": 0.10,
        "suspicious_keywords_in_url": 0.15,
        "long_url": 0.10,
        "at_symbol_redirect": 0.20,
        "domain_age_unknown": 0.05,
    }

    SUSPICIOUS_URL_KEYWORDS = [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "auth",
        "wallet", "payment", "invoice", "claim", "prize",
    ]

    HOMOGRAPH_CHARS = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ϲ": "c",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        url_cfg = self.config.get("detection", {}).get("url", {})
        self.threshold = url_cfg.get("phishing_threshold", 0.5)
        self.suspicious_tlds = url_cfg.get("suspicious_tlds", [])
        self.legitimate_domains = [
            normalize_domain(d) for d in url_cfg.get("legitimate_domains", [])
        ]

    def analyze(self, url: str) -> DetectionResult:
        """Analyze a URL for phishing/fake website indicators."""
        triggered: list[str] = []
        details: dict[str, Any] = {}

        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        parsed = urlparse(url)
        domain = normalize_domain(parsed.netloc.split(":")[0])
        path = parsed.path.lower()

        # Rule 1: Typosquatting
        typosquat_target = self._check_typosquatting(domain)
        if typosquat_target:
            triggered.append("typosquatting")
            details["mimics_domain"] = typosquat_target
            details["actual_domain"] = domain

        # Rule 2: Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                triggered.append("suspicious_tld")
                details["suspicious_tld"] = tld
                break

        # Rule 3: IP address instead of domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            triggered.append("ip_address_url")
            details["ip_address"] = domain

        # Rule 4: Excessive subdomains
        parts = domain.split(".")
        if len(parts) > 4:
            triggered.append("excessive_subdomains")
            details["subdomain_count"] = len(parts) - 2

        # Rule 5: Homograph attack (Unicode lookalikes)
        if self._has_homograph(domain):
            triggered.append("homograph_attack")
            details["homograph_detected"] = True

        # Rule 6: Missing HTTPS
        if parsed.scheme == "http":
            triggered.append("missing_https")
            details["scheme"] = "http"

        # Rule 7: Suspicious keywords in URL
        url_lower = url.lower()
        keyword_hits = [kw for kw in self.SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
        if keyword_hits and domain not in self.legitimate_domains:
            triggered.append("suspicious_keywords_in_url")
            details["keyword_hits"] = keyword_hits[:5]

        # Rule 8: Unusually long URL
        if len(url) > 150:
            triggered.append("long_url")
            details["url_length"] = len(url)

        # Rule 9: @ symbol redirect trick
        if "@" in parsed.netloc or "@" in url:
            triggered.append("at_symbol_redirect")
            details["redirect_trick"] = True

        # Rule 10: DNS resolution check
        dns_result = self._check_dns(domain)
        details["dns_resolves"] = dns_result
        if not dns_result and not re.match(r"^\d", domain):
            triggered.append("domain_age_unknown")
            details["dns_note"] = "Domain does not resolve"

        # Character substitution detection
        char_subs = self._detect_char_substitution(domain)
        if char_subs:
            details["char_substitutions"] = char_subs
            if "typosquatting" not in triggered:
                triggered.append("typosquatting")

        score = score_from_rules(triggered, self.RULE_WEIGHTS)
        return DetectionResult(
            is_phishing=score >= self.threshold,
            confidence=round(score, 3),
            risk_level=DetectionResult.risk_from_score(score),
            triggered_rules=triggered,
            details=details,
        )

    def analyze_batch(self, urls: list[str]) -> list[dict]:
        """Analyze multiple URLs."""
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

    def _check_typosquatting(self, domain: str) -> str | None:
        """Check if domain typosquats a legitimate brand."""
        domain_base = domain.split(".")[0].replace("-", "")
        for legit in self.legitimate_domains:
            legit_base = legit.split(".")[0]
            distance = levenshtein_distance(domain_base, legit_base)
            if 0 < distance <= 3 and domain != legit:
                return legit
            if legit_base in domain_base and domain != legit:
                return legit

        suspicious_patterns = {
            "microsoft.com": r"micros[o0]ft",
            "google.com": r"g[o0]{2}gle",
            "paypal.com": r"paypa[li]",
            "amazon.com": r"amaz[o0]n",
            "apple.com": r"app[li]e",
        }
        for legit, pattern in suspicious_patterns.items():
            if re.search(pattern, domain, re.IGNORECASE):
                return legit
        return None

    def _has_homograph(self, domain: str) -> bool:
        """Detect Unicode homograph characters."""
        for char in domain:
            if ord(char) > 127:
                return True
            if char in self.HOMOGRAPH_CHARS:
                return True
        return False

    def _detect_char_substitution(self, domain: str) -> list[str]:
        """Detect common character substitutions (o->0, l->1)."""
        subs = []
        patterns = [
            (r"0", "o"), (r"1", "l/i"), (r"5", "s"), (r"3", "e"),
        ]
        for pattern, meaning in patterns:
            if re.search(pattern, domain):
                subs.append(f"'{pattern}' used instead of '{meaning}'")
        return subs

    @staticmethod
    def _check_dns(domain: str) -> bool:
        """Check if domain resolves via DNS."""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False
