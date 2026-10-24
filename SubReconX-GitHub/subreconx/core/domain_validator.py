"""Domain name validation and sanitization.

Provides strict validation of user-supplied domain strings to prevent
command injection, reject invalid inputs, and normalize domain names
before they enter the scan pipeline.
"""

import re
import logging
from urllib.parse import urlparse

from subreconx.exceptions import InvalidDomainError

logger = logging.getLogger(__name__)

# RFC 1123 compliant hostname label: alphanumeric, hyphens allowed in middle
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Maximum total domain length per RFC 1035
_MAX_DOMAIN_LENGTH = 253

# Bare TLDs, reserved names, and test domains that should not be scanned
_BLOCKED_INPUTS: frozenset[str] = frozenset({
    # Generic TLDs
    "com", "net", "org", "io", "co", "info", "biz",
    # Government / educational
    "gov", "edu", "mil", "int",
    # Country codes that are too broad
    "us", "uk", "de", "fr", "cn", "ru", "jp", "in",
    # Reserved per RFC 2606
    "localhost", "local", "example", "test", "invalid",
    # Special-use
    "onion", "internal",
})

# Characters that must never appear in a domain — prevents injection
_DANGEROUS_CHARS = frozenset(";|&$`(){}[]!><\n\r\t '\"\\%^")


def sanitize_domain(raw_input: str) -> str:
    """Sanitize user input into a clean domain name.

    Strips whitespace, removes protocol prefixes, paths, ports,
    trailing dots, and lowercases the result.

    Args:
        raw_input: Raw user-provided domain string.

    Returns:
        Cleaned domain string.

    Raises:
        InvalidDomainError: If input is empty after sanitization.
    """
    if not raw_input or not raw_input.strip():
        raise InvalidDomainError("Domain input is empty")

    domain = raw_input.strip().lower()

    # Strip common protocol prefixes
    if "://" in domain:
        try:
            parsed = urlparse(domain)
            extracted = parsed.hostname or parsed.netloc.split(":")[0]
            domain = extracted if extracted else ""
        except Exception:
            # If urlparse fails, try manual stripping
            after = domain.split("://", 1)[1]
            domain = after.split("/")[0].split(":")[0] if after else ""

    # Remove trailing FQDN dot
    domain = domain.rstrip(".")

    # Remove port number
    if ":" in domain:
        domain = domain.split(":")[0]

    # Remove any path or query components
    if "/" in domain:
        domain = domain.split("/")[0]

    # Remove leading wildcard notation
    if domain.startswith("*."):
        domain = domain[2:]

    if not domain:
        raise InvalidDomainError(
            f"No valid domain found after sanitizing input: {raw_input!r}"
        )

    return domain


def validate_domain(domain: str) -> str:
    """Validate and sanitize a domain name for scanning.

    Performs full sanitization, format validation, length checks,
    injection detection, and safety checks.

    Args:
        domain: Domain name to validate.

    Returns:
        Validated and sanitized domain string.

    Raises:
        InvalidDomainError: If the domain fails any validation check.
    """
    domain = sanitize_domain(domain)

    # Reject IP addresses — only domain names are accepted
    if _is_ip_address(domain):
        raise InvalidDomainError(
            f"IP addresses are not accepted; provide a domain name: {domain!r}"
        )

    # Reject command injection patterns early
    _check_injection(domain)

    # Length check
    if len(domain) > _MAX_DOMAIN_LENGTH:
        raise InvalidDomainError(
            f"Domain exceeds maximum length of {_MAX_DOMAIN_LENGTH} chars: "
            f"{domain!r} ({len(domain)} chars)"
        )

    # Must have at least two labels (e.g. example.com)
    labels = domain.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(
            f"Domain must have at least two labels (e.g. example.com): {domain!r}"
        )

    # Validate each label individually
    for label in labels:
        if not label:
            raise InvalidDomainError(
                f"Domain contains an empty label: {domain!r}"
            )
        if len(label) > 63:
            raise InvalidDomainError(
                f"Label exceeds 63-char limit: {label!r} in {domain!r}"
            )
        if not _LABEL_RE.match(label):
            raise InvalidDomainError(
                f"Label contains invalid characters: {label!r} in {domain!r}"
            )

    # Block bare TLDs and reserved names
    if domain in _BLOCKED_INPUTS:
        raise InvalidDomainError(
            f"Bare TLDs and reserved names are not valid scan targets: {domain!r}"
        )

    logger.debug("Domain validated successfully: %s", domain)
    return domain


def is_valid_hostname(hostname: str) -> bool:
    """Check whether a string is a syntactically valid hostname.

    Does not perform DNS resolution. Accepts subdomains of any depth.

    Args:
        hostname: Hostname string to check.

    Returns:
        True if the hostname is syntactically valid.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    hostname = hostname.lower().strip().rstrip(".")

    if len(hostname) > _MAX_DOMAIN_LENGTH:
        return False

    labels = hostname.split(".")

    if len(labels) < 2:
        return False

    return all(
        bool(label) and len(label) <= 63 and _LABEL_RE.match(label) is not None
        for label in labels
    )


def _is_ip_address(value: str) -> bool:
    """Check if a string looks like an IPv4 or IPv6 address.

    Uses pattern matching rather than socket parsing to avoid
    any system calls on untrusted input.
    """
    # IPv4: four groups of 1-3 digits separated by dots
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return True

    # IPv6: contains colons and only hex digits / colons
    if ":" in value and all(c in "0123456789abcdef:." for c in value):
        return True

    return False


def _check_injection(domain: str) -> None:
    """Detect command injection patterns in domain input.

    Args:
        domain: Domain string to inspect.

    Raises:
        InvalidDomainError: If suspicious characters are found.
    """
    found = _DANGEROUS_CHARS.intersection(domain)
    if found:
        # Sort for deterministic error messages in tests
        chars_display = ", ".join(sorted(repr(c) for c in found))
        raise InvalidDomainError(
            f"Domain contains suspicious characters [{chars_display}]: {domain!r}"
        )
