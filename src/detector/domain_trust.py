"""Shared domain trust and phishing domain analysis."""

import re
from src.utils.helpers import levenshtein_distance, normalize_domain

TRUSTED_TLDS = {
    ".com", ".org", ".net", ".io", ".in", ".ai", ".co", ".dev", ".app",
    ".edu", ".gov", ".uk", ".us", ".ca", ".de", ".fr", ".au", ".co.in",
    ".com.in", ".me", ".info", ".biz",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".buzz", ".cam", ".rest", ".surf",
}

BRAND_TYPOSQUAT_PATTERNS = [
    (r"micros[o0]?ft|microsft", "microsoft.com"),
    (r"g[o0]{2}gle", "google.com"),
    (r"paypa[li]1|paypa1", "paypal.com"),
    (r"amaz[o0]n", "amazon.com"),
    (r"app[li1]e", "apple.com"),
    (r"app1e", "apple.com"),
    (r"netfl[1i]x", "netflix.com"),
    (r"quickb[o0]{2}ks", "quickbooks.com"),
]

BRAND_NAMES = {
    "microsoft", "windows", "google", "paypal", "amazon", "apple",
    "netflix", "facebook", "instagram", "linkedin", "github", "chase",
    "wellsfargo", "bankofamerica", "quickbooks", "dropbox", "spotify",
}

SECURITY_WORDS = {
    "secure", "security", "verify", "login", "signin", "account",
    "update", "confirm", "billing", "alert", "support", "auth",
    "password", "credential", "restore", "reactivate", "suspend",
}

PHISHING_PATH_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "credential", "auth",
    "wallet", "payment", "invoice", "claim", "prize", "winner",
}

DEFAULT_LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "paypal.com", "apple.com",
    "facebook.com", "linkedin.com", "github.com", "gitlab.com", "stackoverflow.com",
    "netflix.com", "twitter.com", "x.com", "instagram.com", "whatsapp.com",
    "outlook.com", "gmail.com", "yahoo.com", "dropbox.com", "slack.com",
    "zoom.us", "adobe.com", "spotify.com", "reddit.com", "medium.com",
    "notion.so", "figma.com", "vercel.app", "herokuapp.com", "googleusercontent.com",
    "amazonaws.com", "cloudflare.com", "wikipedia.org", "openai.com",
    "windows.com", "live.com", "office.com",
]


def normalize_domain_chars(domain: str) -> str:
    replacements = {"0": "o", "1": "l", "5": "s", "3": "e"}
    result = domain.lower()
    for char, repl in replacements.items():
        result = result.replace(char, repl)
    return result


def get_tld(domain: str) -> str:
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
    domain = normalize_domain(domain)
    all_trusted = [normalize_domain(d) for d in whitelist + DEFAULT_LEGITIMATE_DOMAINS]
    for trusted in all_trusted:
        if domain == trusted or domain.endswith(f".{trusted}"):
            return True
    return False


def domain_labels(domain: str) -> list[str]:
    """Split domain into checkable labels (handles hyphens)."""
    base = domain.split(".")[0]
    return [p for p in re.split(r"[-_]", base) if len(p) >= 3]


def check_brand_typosquat(domain: str) -> str | None:
    for pattern, brand in BRAND_TYPOSQUAT_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            return brand
    return None


def check_edit_distance_typosquat(domain: str, whitelist: list[str]) -> str | None:
    """Flag close misspellings of brand names on each domain label."""
    all_brands = [normalize_domain(d) for d in whitelist + DEFAULT_LEGITIMATE_DOMAINS]
    brand_bases = {legit.split(".")[0] for legit in all_brands if len(legit.split(".")[0]) >= 4}

    if domain in all_brands:
        return None

    labels = domain_labels(domain) + [normalize_domain_chars(domain.split(".")[0].replace("-", ""))]

    for label in labels:
        normalized_label = normalize_domain_chars(label)
        if len(normalized_label) < 4:
            continue
        for brand_base in brand_bases:
            if normalized_label == brand_base:
                for legit in all_brands:
                    if legit.split(".")[0] == brand_base and domain != legit:
                        return legit
            distance = levenshtein_distance(normalized_label, brand_base)
            if 0 < distance <= 2:
                return f"{brand_base}.com"
    return None


def check_brand_impersonation(domain: str) -> str | None:
    """
    Detect domains combining a brand name with security/login words.
    e.g. windows-security-alert.com, paypa1-secure.com
    """
    if is_known_legitimate(domain, []):
        return None

    labels = set(domain_labels(domain))
    domain_lower = domain.lower()

    for brand in BRAND_NAMES:
        if brand in domain_lower and not is_known_legitimate(domain, [f"{brand}.com"]):
            security_hits = [w for w in SECURITY_WORDS if w in labels or w in domain_lower]
            if security_hits:
                return f"{brand}.com (impersonation)"

    # Hyphenated security-login patterns without exact brand but clearly phishing
    security_hits = [w for w in SECURITY_WORDS if w in labels]
    if len(security_hits) >= 2:
        return "security-phishing-pattern"

    return None


def analyze_domain(domain: str, whitelist: list[str] | None = None) -> dict:
    """
    Analyze a domain for phishing signals.
    Returns dict with is_phishing, confidence, rules, details.
    """
    whitelist = whitelist or []
    domain = normalize_domain(domain)
    rules: list[str] = []
    details: dict = {"domain": domain, "tld": get_tld(domain)}

    if is_known_legitimate(domain, whitelist):
        return {
            "is_phishing": False,
            "confidence": 0.05,
            "rules": [],
            "details": {**details, "trust_reason": "Known legitimate domain"},
        }

    brand = check_brand_typosquat(domain)
    if brand:
        rules.append("brand_typosquat")
        details["mimics_brand"] = brand

    edit = check_edit_distance_typosquat(domain, whitelist)
    if edit and "brand_typosquat" not in rules:
        rules.append("edit_distance_typosquat")
        details["similar_to"] = edit

    impersonation = check_brand_impersonation(domain)
    if impersonation and "brand_typosquat" not in rules:
        rules.append("brand_impersonation")
        details["impersonation"] = impersonation

    if is_suspicious_tld(domain):
        rules.append("suspicious_tld")
        details["suspicious_tld"] = True

    # Trusted .com/.io without phishing signals → safe
    strong_rules = {"brand_typosquat", "edit_distance_typosquat", "brand_impersonation"}
    has_strong = bool(set(rules) & strong_rules)

    if is_trusted_tld(domain) and not has_strong:
        return {
            "is_phishing": False,
            "confidence": 0.1 if rules else 0.05,
            "rules": [r for r in rules if r not in strong_rules],
            "details": {**details, "trust_reason": "Trusted TLD without impersonation"},
        }

    if "suspicious_tld" in rules and has_strong:
        rules.append("suspicious_tld_confirmed")

    weights = {
        "brand_typosquat": 0.55,
        "edit_distance_typosquat": 0.50,
        "brand_impersonation": 0.50,
        "suspicious_tld": 0.20,
        "suspicious_tld_confirmed": 0.15,
    }
    score = min(sum(weights.get(r, 0.1) for r in rules), 1.0)
    is_phishing = has_strong or ("suspicious_tld" in rules and score >= 0.35)

    return {
        "is_phishing": is_phishing,
        "confidence": round(score, 3),
        "rules": rules,
        "details": details,
    }
