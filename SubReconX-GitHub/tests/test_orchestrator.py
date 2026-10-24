"""Tests for ScanOrchestrator pipeline."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from subreconx.core.orchestrator import ScanOrchestrator
from subreconx.db.database import Database
from subreconx.db.migrations import check_and_migrate
from subreconx.db.repositories import ScanRepository
from subreconx.models import (
    DNSResult,
    HTTPResult,
    ScanConfig,
    ScanStatus,
    SubdomainRecord,
)


@pytest.fixture
async def orchestrator(tmp_path):
    db_file = tmp_path / "orch_test.db"
    db = Database(db_file)
    await check_and_migrate(db)
    repo = ScanRepository(db)
    return ScanOrchestrator(repo)


@pytest.mark.asyncio
async def test_orchestrator_pipeline_mocked(orchestrator: ScanOrchestrator) -> None:
    config = ScanConfig(
        domain="example.com",
        enable_dns=True,
        enable_http=True,
        use_subfinder=True,
        use_amass=False,
    )

    mock_discovered = [
        SubdomainRecord(hostname="api.example.com", source="subfinder"),
        SubdomainRecord(hostname="out-of-scope.com", source="subfinder"),
    ]

    mock_dns = [
        DNSResult(hostname="api.example.com", is_resolved=True),
        DNSResult(hostname="example.com", is_resolved=True),
    ]

    mock_http = [
        HTTPResult(
            hostname="api.example.com",
            url="https://api.example.com",
            scheme="https",
            status_code=200,
        )
    ]

    with patch("subreconx.core.discovery.subfinder.SubfinderEngine.is_available", new_callable=AsyncMock) as m_avail, \
         patch("subreconx.core.discovery.subfinder.SubfinderEngine.discover", new_callable=AsyncMock) as m_disc, \
         patch("subreconx.core.dns_resolver.DNSResolverEngine.detect_wildcard", new_callable=AsyncMock) as m_wild, \
         patch("subreconx.core.dns_resolver.DNSResolverEngine.resolve_batch", new_callable=AsyncMock) as m_dns, \
         patch("subreconx.core.http_prober.HTTPProber.probe_batch", new_callable=AsyncMock) as m_http:

        m_avail.return_value = True
        m_disc.return_value = mock_discovered
        m_wild.return_value = False
        m_dns.return_value = mock_dns
        m_http.return_value = mock_http

        result = await orchestrator.run_scan(config, scan_id="test_orch_scan")

        assert result.summary.status == ScanStatus.COMPLETED
        assert result.summary.domain == "example.com"
        assert result.summary.total_subdomains >= 2  # api.example.com and base example.com
        # out-of-scope.com should have been rejected by scope
        assert not any(s.hostname == "out-of-scope.com" for s in result.subdomains)
        assert result.summary.dns_resolved == 2
        assert result.summary.https_live == 1
