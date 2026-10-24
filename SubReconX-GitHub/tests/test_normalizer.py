"""Tests for hostname normalization and deduplication."""

from datetime import datetime, timezone
import pytest

from subreconx.core.normalizer import (
    deduplicate_subdomains,
    merge_sources,
    normalize_and_deduplicate,
    normalize_hostname,
)
from subreconx.models import SubdomainRecord


class TestNormalizeHostname:
    """Test hostname cleaning rules."""

    def test_basic_subdomain(self) -> None:
        assert normalize_hostname("api.example.com") == "api.example.com"

    def test_uppercase_lowered(self) -> None:
        assert normalize_hostname("API.EXAMPLE.COM") == "api.example.com"

    def test_trailing_dot_removed(self) -> None:
        assert normalize_hostname("api.example.com.") == "api.example.com"

    def test_wildcard_prefix_removed(self) -> None:
        assert normalize_hostname("*.api.example.com") == "api.example.com"

    def test_leading_dot_removed(self) -> None:
        assert normalize_hostname(".api.example.com") == "api.example.com"

    def test_url_prefix_stripped(self) -> None:
        assert normalize_hostname("https://api.example.com/login") == "api.example.com"

    def test_port_stripped(self) -> None:
        assert normalize_hostname("api.example.com:8443") == "api.example.com"

    def test_invalid_hostname_returns_empty(self) -> None:
        assert normalize_hostname("not an invalid domain!") == ""
        assert normalize_hostname("") == ""


class TestDeduplicationAndMerge:
    """Test deduplicating and merging source attributions."""

    def test_deduplicate_subdomains_preserves_order(self) -> None:
        now = datetime.now(timezone.utc)
        records = [
            SubdomainRecord(hostname="b.example.com", source="subfinder", discovered_at=now),
            SubdomainRecord(hostname="a.example.com", source="subfinder", discovered_at=now),
            SubdomainRecord(hostname="b.example.com", source="amass", discovered_at=now),
        ]
        deduped = deduplicate_subdomains(records)
        assert len(deduped) == 2
        assert deduped[0].hostname == "b.example.com"
        assert deduped[1].hostname == "a.example.com"

    def test_merge_sources(self) -> None:
        t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

        records = [
            SubdomainRecord(hostname="api.example.com", source="subfinder", discovered_at=t2),
            SubdomainRecord(hostname="api.example.com", source="amass", discovered_at=t1),
        ]

        merged = merge_sources(records)
        assert len(merged) == 1
        rec = merged["api.example.com"]
        assert rec.hostname == "api.example.com"
        assert rec.source == "amass,subfinder"
        assert rec.discovered_at == t1

    def test_normalize_and_deduplicate_pipeline(self) -> None:
        now = datetime.now(timezone.utc)
        records = [
            SubdomainRecord(hostname="*.Beta.example.com.", source="subfinder", discovered_at=now),
            SubdomainRecord(hostname="alpha.example.com", source="amass", discovered_at=now),
            SubdomainRecord(hostname="invalid..hostname", source="manual", discovered_at=now),
            SubdomainRecord(hostname="beta.example.com", source="amass", discovered_at=now),
        ]

        result = normalize_and_deduplicate(records)
        assert len(result) == 2
        assert result[0].hostname == "alpha.example.com"
        assert result[1].hostname == "beta.example.com"
        assert result[1].source == "amass,subfinder"
