import hashlib
import ipaddress
from urllib.parse import urlparse, urlunparse
import tldextract


def normalize_url(url: str) -> str:
    """
    Normalize a URL to canonical form before hashing.
    Steps: strip whitespace, lowercase scheme+host,
    strip trailing slash from path, remove fragment.
    """
    url    = url.strip() #remove spaces
    parsed = urlparse(url.lower()) #urlparse function split the url into many sections ( objetc with attributes)

    clean_path = parsed.path.rstrip("/") or "/"
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        clean_path,
        parsed.params,
        parsed.query,
        "",             # Remove fragment — client-side only
    ))
    return normalized


def hash_url(normalized_url: str) -> str:
    """Return SHA-256 hex digest of the normalized URL."""
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def extract_domain(url: str) -> str:
    """Extract registered domain from URL (e.g. 'evil.com' from 'sub.evil.com')."""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}".lower()


def is_private_target(url: str) -> bool:
    """
    Returns True if the URL hostname is a private, loopback,
    or link-local IP address — used to detect SSRF probes.
    Returns False for domain names (not raw IPs).
    """
    try:
        host = urlparse(url).hostname
        ip   = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, TypeError):
        return False  # It's a domain name — check passes