"""Email phishing detection using rule-based filters and heuristics."""

import re
from typing import Any

from src.utils.helpers import extract_urls, normalize_domain
from .domain_trust import (
    check_brand_typosquat,
    check_edit_distance_typosquat,
    is_known_legitimate,
    is_suspicious_tld,
)
from .rules import DetectionResult, score_from_rules


class EmailPhishingDetector:
    """Detects phishing indicators in email content."""

    RULE_WEIGHTS = {
        "suspicious_sender_domain": 0.25,
        "display_name_mismatch": 0.15,
        "urgency_keywords": 0.15,
        "suspicious_url_in_body": 0.25,
        "generic_greeting": 0.10,
        "threat_language": 0.15,
        "excessive_caps": 0.10,
        "hidden_url_mismatch": 0.20,
        "suspicious_attachment_reference": 0.10,
        "reply_to_mismatch": 0.15,
    }

    URGENCY_PATTERNS = [
        r"\burgent\b",
        r"\bimmediate(ly)?\b",
        r"\bact now\b",
        r"\blimited time\b",
        r"\bwithin \d+ hours?\b",
        r"\bexpire[sd]?\b",
        r"\bfinal notice\b",
        r"\bverify (your )?account\b",
        r"\bconfirm your identity\b",
        r"\bsuspended\b",
        r"\blocked\b",
        r"\bunauthorized\b",
    ]

    THREAT_PATTERNS = [
        r"\baccount (will be )?(closed|terminated|suspended|deleted)\b",
        r"\bpermanent(ly)? (close|suspend|delete)\b",
        r"\bdata (loss|breach|at risk)\b",
        r"\bvirus(es)? detected\b",
        r"\binfected\b",
        r"\blegal action\b",
    ]

    GENERIC_GREETINGS = [
        r"^dear user\b",
        r"^dear customer\b",
        r"^dear member\b",
        r"^hello,\s*$",
        r"^hi there\b",
        r"^dear sir/madam\b",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        email_cfg = self.config.get("detection", {}).get("email", {})
        self.threshold = email_cfg.get("phishing_threshold", 0.5)
        self.suspicious_keywords = email_cfg.get("suspicious_keywords", [])
        self.trusted_domains = [
            normalize_domain(d) for d in email_cfg.get("trusted_domains", [])
        ]
        self.url_whitelist = [
            normalize_domain(d)
            for d in self.config.get("detection", {}).get("url", {}).get("legitimate_domains", [])
        ]

    def analyze(
        self,
        subject: str,
        body: str,
        from_address: str = "",
        from_display: str = "",
        reply_to: str = "",
    ) -> DetectionResult:
        """Analyze email content for phishing indicators."""
        triggered: list[str] = []
        details: dict[str, Any] = {}
        full_text = f"{subject}\n{body}".lower()

        # Rule 1: Suspicious sender domain
        sender_domain = normalize_domain(from_address.split("@")[-1]) if "@" in from_address else ""
        if sender_domain and not self._is_trusted_or_subdomain(sender_domain):
            if self._looks_like_typosquat(sender_domain):
                triggered.append("suspicious_sender_domain")
                details["sender_domain"] = sender_domain
                details["typosquat_suspected"] = True

        # Rule 2: Display name vs email mismatch
        if from_display and from_address:
            display_lower = from_display.lower()
            brand_keywords = ["microsoft", "google", "paypal", "amazon", "apple", "netflix", "bank"]
            for brand in brand_keywords:
                if brand in display_lower and brand not in sender_domain:
                    triggered.append("display_name_mismatch")
                    details["display_brand"] = brand
                    details["actual_domain"] = sender_domain
                    break

        # Rule 3: Urgency keywords
        urgency_hits = []
        for pattern in self.URGENCY_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                urgency_hits.append(pattern)
        for kw in self.suspicious_keywords:
            if kw.lower() in full_text:
                urgency_hits.append(kw)
        if urgency_hits:
            triggered.append("urgency_keywords")
            details["urgency_matches"] = urgency_hits[:5]

        # Rule 4: Suspicious URLs in body (skip known .com/.io/.in legitimate sites)
        urls = extract_urls(body)
        suspicious_urls = []
        for url in urls:
            url_domain = self._domain_from_url(url)
            if not url_domain:
                continue
            if is_known_legitimate(url_domain, self.url_whitelist + self.trusted_domains):
                continue
            if check_brand_typosquat(url_domain) or check_edit_distance_typosquat(
                url_domain, self.url_whitelist
            ):
                suspicious_urls.append(url)
            elif is_suspicious_tld(url_domain):
                suspicious_urls.append(url)
        if suspicious_urls:
            triggered.append("suspicious_url_in_body")
            details["suspicious_urls"] = suspicious_urls

        # Rule 5: Generic greeting
        for pattern in self.GENERIC_GREETINGS:
            if re.search(pattern, body.strip(), re.IGNORECASE | re.MULTILINE):
                triggered.append("generic_greeting")
                break

        # Rule 6: Threat language
        threat_hits = [p for p in self.THREAT_PATTERNS if re.search(p, full_text, re.IGNORECASE)]
        if threat_hits:
            triggered.append("threat_language")
            details["threat_matches"] = len(threat_hits)

        # Rule 7: Excessive caps in subject
        if subject and len(subject) > 10:
            caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
            if caps_ratio > 0.5:
                triggered.append("excessive_caps")
                details["caps_ratio"] = round(caps_ratio, 2)

        # Rule 8: Hidden URL mismatch (href != display text pattern)
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, body, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("http") and "@" in href:
                triggered.append("hidden_url_mismatch")
                details["hidden_redirect"] = href
                break

        # Rule 9: Attachment references with urgency
        if re.search(r"\b(attached|attachment|download|\.exe|\.zip|\.scr)\b", full_text, re.IGNORECASE):
            if "urgency_keywords" in triggered:
                triggered.append("suspicious_attachment_reference")

        # Rule 10: Reply-to mismatch
        if reply_to and from_address:
            reply_domain = normalize_domain(reply_to.split("@")[-1]) if "@" in reply_to else ""
            if reply_domain and reply_domain != sender_domain:
                triggered.append("reply_to_mismatch")
                details["reply_to"] = reply_to

        score = score_from_rules(triggered, self.RULE_WEIGHTS)
        return DetectionResult(
            is_phishing=score >= self.threshold,
            confidence=round(score, 3),
            risk_level=DetectionResult.risk_from_score(score),
            triggered_rules=triggered,
            details=details,
        )

    def analyze_email_dict(self, email: dict) -> DetectionResult:
        """Analyze email from dictionary structure."""
        return self.analyze(
            subject=email.get("subject", ""),
            body=email.get("body", ""),
            from_address=email.get("from_address", email.get("from", "")),
            from_display=email.get("from_display", ""),
            reply_to=email.get("reply_to", ""),
        )

    def _is_trusted_or_subdomain(self, domain: str) -> bool:
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith(f".{trusted}"):
                return True
        return False

    def _looks_like_typosquat(self, domain: str) -> bool:
        """Detect sender domain typosquatting (strict — avoids false positives)."""
        if check_brand_typosquat(domain):
            return True
        if check_edit_distance_typosquat(domain, self.trusted_domains + self.url_whitelist):
            return True
        return bool(re.search(
            r"(secure-|[-_]verify|[-_]login|paypa[li]1|micros[o0]ft|g[o0]{2}gle)",
            domain,
            re.IGNORECASE,
        ))

    @staticmethod
    def _domain_from_url(url: str) -> str:
        from src.utils.helpers import domain_from_url
        return domain_from_url(url)
