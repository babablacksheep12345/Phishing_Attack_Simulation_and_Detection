"""Shared utility functions."""

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load YAML configuration file."""
    if config_path is None:
        config_path = Path(__file__).resolve().parents[2] / "config" / "settings.yaml"
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def normalize_domain(domain: str) -> str:
    """Normalize domain for comparison."""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""
    pattern = r"https?://[^\s<>\"']+"
    return re.findall(pattern, text, re.IGNORECASE)


def extract_email_addresses(text: str) -> list[str]:
    """Extract email addresses from text."""
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return re.findall(pattern, text)


def domain_from_url(url: str) -> str:
    """Extract registered domain from URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc or parsed.path.split("/")[0]
    return normalize_domain(host.split(":")[0])


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]
