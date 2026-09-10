"""Shared domain trust and TLD classification for phishing detection."""

import re
from src.utils.helpers import levenshtein_distance, normalize_domain

# Common legitimate TLDs — presence alone does NOT mean phishing
TRUSTED_TLDS = {
    ".com", ".org", ".net", ".io", ".in", ".ai", ".co", ".dev", ".app",
    ".edu", ".gov", ".uk", ".us", ".ca", ".de", ".fr", ".au", ".co.in",
    ".com.in", ".me", ".info", ".biz",
}

# TLDs often abused for phishing — worth extra scrutiny (not auto-block)
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".buzz", ".cam", ".rest", ".surf",
}

# Known brand impersonation patterns (strong signal)
BRAND_TYPOSQUAT_PATTERNS = [
    (r"micros[o0]ft", "microsoft.com"),
    (r"g[o0]{2}gle", "google.com"),
    (r"paypa[li]1|paypa1", "paypal.com"),
    (r"amaz[o0]n", "amazon.com"),
    (r"app[li]e", "apple.com"),
    (r"netfl[1i]x", "netflix.com"),
    (r"quickb[o0]{2}ks", "quickbooks.com"),
]

DEFAULT_LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "paypal.com", "apple.com",
    "facebook.com", "linkedin.com", "github.com", "gitlab.com", "stackoverflow.com",
    "netflix.com", "twitter.com", "x.com", "instagram.com", "whatsapp.com",
    "outlook.com", "gmail.com", "yahoo.com", "dropbox.com", "slack.com",
    "zoom.us", "adobe.com", "spotify.com", "reddit.com", "medium.com",
    "notion.so", "figma.com", "vercel.app", "herokuapp.com", "googleusercontent.com",
    "amazonaws.com", "cloudflare.com", "wikipedia.org", "openai.com",
]


def normalize_domain_chars(domain: str) -> str:
    """Normalize 0->o, 1->l style substitutions for comparison."""
    replacements = {"0": "o", "1": "l", "5": "s", "3": "e"}
    result = domain.lower()
    for char, repl in replacements.items():
        result = result.replace(char, repl)
    return result


def get_tld(domain: str) -> str:
    """Extract TLD from domain (handles .co.in style)."""
    domain = normalize_domain(domain)
    for compound in (".co.in", ".com.in", ".co.uk"):
        if domain.endswith(compound):
            return compound
    parts = domain.rsplit(".", 1)
    return f".{parts[-1]}" if len(parts) > 1 else ""


def is_trusted_tld(domain: str) -> bool:
    return get_tld(domain) in TRUSTED_TLDS


def is_suspicious_tld(domain: str) -> bool:
    return get_tld(domain) in SUSPICIOUS_TLDS


def is_known_legitimate(domain: str, whitelist: list[str]) -> bool:
    """True if domain exactly matches or is a subdomain of a whitelisted domain."""
    domain = normalize_domain(domain)
    all_trusted = [normalize_domain(d) for d in whitelist + DEFAULT_LEGITIMATE_DOMAINS]
    for trusted in all_trusted:
        if domain == trusted or domain.endswith(f".{trusted}"):
            return True
    return False


def check_brand_typosquat(domain: str) -> str | None:
    """Return mimicked brand if domain matches known impersonation pattern."""
    for pattern, brand in BRAND_TYPOSQUAT_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            return brand
    return None


def check_edit_distance_typosquat(domain: str, whitelist: list[str]) -> str | None:
    """
    Flag only close misspellings of brand names (edit distance 1-2).
    Does NOT flag unrelated domains that merely contain a substring.
    """
    domain_base = normalize_domain_chars(domain.split(".")[0].replace("-", ""))
    if len(domain_base) < 4:
        return None

    all_brands = [normalize_domain(d) for d in whitelist + DEFAULT_LEGITIMATE_DOMAINS]
    seen_bases: set[str] = set()

    for legit in all_brands:
        brand_base = legit.split(".")[0]
        if brand_base in seen_bases or len(brand_base) < 4:
            continue
        seen_bases.add(brand_base)

        if domain == legit:
            continue

        distance = levenshtein_distance(domain_base, brand_base)
        # Only very close typos — not partial substring matches
        if 0 < distance <= 2:
            return legit

    return None
