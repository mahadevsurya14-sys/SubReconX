"""Tests for DNS resolver engine with mocked resolution."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

import dns.exception
import dns.rdatatype
import dns.resolver

from subreconx.core.dns_resolver import DNSResolverEngine


@pytest.mark.asyncio
async def test_dns_resolve_hostname_success() -> None:
    engine = DNSResolverEngine(resolvers=["8.8.8.8"], timeout=2.0, concurrency=10)

    # Mock answer for A record
    mock_rdata = MagicMock()
    mock_rdata.to_text.return_value = "93.184.216.34"

    mock_answer = MagicMock()
    mock_answer.rrset.ttl = 300
    mock_answer.__iter__.return_value = [mock_rdata]

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer

        res = await engine.resolve_hostname("api.example.com")
        assert res.hostname == "api.example.com"
        assert res.is_resolved is True
        assert len(res.records) >= 1
        assert res.records[0].value == "93.184.216.34"
        assert res.error is None


@pytest.mark.asyncio
async def test_dns_resolve_nxdomain() -> None:
    engine = DNSResolverEngine(resolvers=["8.8.8.8"], timeout=2.0)

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        res = await engine.resolve_hostname("nonexistent.example.com")
        assert res.hostname == "nonexistent.example.com"
        assert res.is_resolved is False
        assert len(res.records) == 0
        assert res.error == "NXDOMAIN"


@pytest.mark.asyncio
async def test_wildcard_detection() -> None:
    engine = DNSResolverEngine(resolvers=["8.8.8.8"], timeout=2.0)

    # When random host resolves, detect_wildcard returns True
    mock_answer = MagicMock()
    mock_answer.__len__.return_value = 1

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer
        is_wild = await engine.detect_wildcard("example.com")
        assert is_wild is True

        # When random host throws NXDOMAIN, detect_wildcard returns False
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        is_wild_false = await engine.detect_wildcard("example.com")
        assert is_wild_false is False
