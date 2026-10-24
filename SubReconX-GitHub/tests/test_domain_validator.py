"""Tests for domain validation and sanitization."""

import pytest

from subreconx.core.domain_validator import (
    sanitize_domain,
    validate_domain,
    is_valid_hostname,
)
from subreconx.exceptions import InvalidDomainError


class TestSanitizeDomain:
    """Test the sanitize_domain function."""

    def test_basic_domain(self) -> None:
        assert sanitize_domain("example.com") == "example.com"

    def test_uppercase_lowered(self) -> None:
        assert sanitize_domain("EXAMPLE.COM") == "example.com"

    def test_whitespace_stripped(self) -> None:
        assert sanitize_domain("  example.com  ") == "example.com"

    def test_http_prefix_removed(self) -> None:
        assert sanitize_domain("http://example.com") == "example.com"

    def test_https_prefix_removed(self) -> None:
        assert sanitize_domain("https://example.com") == "example.com"

    def test_path_removed(self) -> None:
        assert sanitize_domain("https://example.com/path/page") == "example.com"

    def test_port_removed(self) -> None:
        assert sanitize_domain("example.com:8080") == "example.com"

    def test_url_with_port_and_path(self) -> None:
        assert sanitize_domain("https://example.com:443/api") == "example.com"

    def test_trailing_dot_removed(self) -> None:
        assert sanitize_domain("example.com.") == "example.com"

    def test_wildcard_prefix_removed(self) -> None:
        assert sanitize_domain("*.example.com") == "example.com"

    def test_empty_string_raises(self) -> None:
        with pytest.raises(InvalidDomainError, match="empty"):
            sanitize_domain("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(InvalidDomainError, match="empty"):
            sanitize_domain("   ")

    def test_protocol_only_raises(self) -> None:
        with pytest.raises(InvalidDomainError):
            sanitize_domain("https://")


class TestValidateDomain:
    """Test the validate_domain function."""

    # ── Valid domains ────────────────────────────────────────────

    def test_simple_domain(self) -> None:
        assert validate_domain("example.com") == "example.com"

    def test_subdomain_accepted(self) -> None:
        assert validate_domain("sub.example.com") == "sub.example.com"

    def test_deep_subdomain(self) -> None:
        result = validate_domain("a.b.c.d.example.com")
        assert result == "a.b.c.d.example.com"

    def test_hyphenated_labels(self) -> None:
        assert validate_domain("my-site.example.com") == "my-site.example.com"

    def test_numeric_labels(self) -> None:
        assert validate_domain("123.example.com") == "123.example.com"

    def test_sanitization_applied(self) -> None:
        """validate_domain should apply sanitization first."""
        assert validate_domain("  HTTPS://Example.COM/  ") == "example.com"

    # ── IP addresses rejected ────────────────────────────────────

    def test_ipv4_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="IP address"):
            validate_domain("192.168.1.1")

    def test_ipv4_with_protocol_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="IP address"):
            validate_domain("http://10.0.0.1")

    # ── Single label rejected ────────────────────────────────────

    def test_single_label_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="at least two labels"):
            validate_domain("localhost-thing")

    # ── Blocked names ────────────────────────────────────────────

    def test_bare_tld_rejected(self) -> None:
        with pytest.raises(InvalidDomainError):
            validate_domain("com")

    def test_reserved_name_rejected(self) -> None:
        with pytest.raises(InvalidDomainError):
            validate_domain("localhost")

    def test_test_tld_rejected(self) -> None:
        with pytest.raises(InvalidDomainError):
            validate_domain("test")

    # ── Invalid characters ───────────────────────────────────────

    def test_underscore_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="invalid characters"):
            validate_domain("my_site.example.com")

    def test_space_in_domain_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("example .com")

    # ── Injection patterns ───────────────────────────────────────

    def test_semicolon_injection_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("example.com; rm -rf /")

    def test_pipe_injection_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("example.com | cat /etc/passwd")

    def test_backtick_injection_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("`whoami`.example.com")

    def test_dollar_injection_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("$(id).example.com")

    def test_newline_injection_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="suspicious characters"):
            validate_domain("example.com\nmalicious")

    # ── Length limits ────────────────────────────────────────────

    def test_label_too_long_rejected(self) -> None:
        long_label = "a" * 64
        with pytest.raises(InvalidDomainError, match="63-char limit"):
            validate_domain(f"{long_label}.example.com")

    def test_max_length_label_accepted(self) -> None:
        label_63 = "a" * 63
        result = validate_domain(f"{label_63}.example.com")
        assert result == f"{label_63}.example.com"

    def test_domain_too_long_rejected(self) -> None:
        # Build a domain > 253 chars
        labels = ["a" * 60] * 5  # 5 × 60 + 4 dots = 304 chars
        long_domain = ".".join(labels) + ".com"
        with pytest.raises(InvalidDomainError, match="maximum length"):
            validate_domain(long_domain)

    # ── Empty labels ─────────────────────────────────────────────

    def test_empty_label_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="empty label"):
            validate_domain("example..com")

    # ── Leading/trailing hyphens ─────────────────────────────────

    def test_leading_hyphen_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="invalid characters"):
            validate_domain("-example.com")

    def test_trailing_hyphen_rejected(self) -> None:
        with pytest.raises(InvalidDomainError, match="invalid characters"):
            validate_domain("example-.com")


class TestIsValidHostname:
    """Test the is_valid_hostname helper."""

    def test_valid_hostname(self) -> None:
        assert is_valid_hostname("api.example.com") is True

    def test_valid_deep_hostname(self) -> None:
        assert is_valid_hostname("a.b.c.example.com") is True

    def test_single_label_invalid(self) -> None:
        assert is_valid_hostname("example") is False

    def test_empty_invalid(self) -> None:
        assert is_valid_hostname("") is False

    def test_none_invalid(self) -> None:
        assert is_valid_hostname(None) is False  # type: ignore[arg-type]

    def test_too_long_invalid(self) -> None:
        long = "a" * 254
        assert is_valid_hostname(long) is False

    def test_trailing_dot_accepted(self) -> None:
        """FQDN trailing dot should be stripped and accepted."""
        assert is_valid_hostname("example.com.") is True

    def test_uppercase_accepted(self) -> None:
        """Hostnames should be case-insensitive."""
        assert is_valid_hostname("API.Example.COM") is True

    def test_hyphen_accepted(self) -> None:
        assert is_valid_hostname("my-api.example.com") is True

    def test_underscore_rejected(self) -> None:
        assert is_valid_hostname("my_api.example.com") is False

    def test_special_chars_rejected(self) -> None:
        assert is_valid_hostname("api!.example.com") is False
