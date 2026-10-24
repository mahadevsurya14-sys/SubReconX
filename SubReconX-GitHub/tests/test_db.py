"""Tests for database layer and repositories."""

from datetime import datetime, timezone
import pytest

from subreconx.db.database import Database
from subreconx.db.migrations import check_and_migrate
from subreconx.db.repositories import ScanRepository
from subreconx.models import (
    DNSRecord,
    DNSResult,
    HTTPResult,
    ScanConfig,
    ScanStatus,
    ScanSummary,
    SubdomainRecord,
)


@pytest.fixture
async def repo(tmp_path):
    db_file = tmp_path / "test_repo.db"
    db = Database(db_file)
    await check_and_migrate(db)
    return ScanRepository(db)


@pytest.mark.asyncio
async def test_create_and_get_scan(repo: ScanRepository) -> None:
    config = ScanConfig(domain="example.com", enable_dns=True)
    await repo.create_scan("scan123", "example.com", config)

    scan_data = await repo.get_scan("scan123")
    assert scan_data is not None
    assert scan_data["id"] == "scan123"
    assert scan_data["domain"] == "example.com"
    assert scan_data["status"] == ScanStatus.RUNNING.value

    # Update status
    summary = ScanSummary(
        scan_id="scan123",
        domain="example.com",
        status=ScanStatus.COMPLETED,
        total_subdomains=5,
    )
    await repo.update_scan_status("scan123", ScanStatus.COMPLETED, summary=summary)

    updated = await repo.get_scan("scan123")
    assert updated["status"] == ScanStatus.COMPLETED.value
    assert "summary_json" in updated


@pytest.mark.asyncio
async def test_subdomain_crud(repo: ScanRepository) -> None:
    config = ScanConfig(domain="example.com")
    await repo.create_scan("scan_sub", "example.com", config)

    records = [
        SubdomainRecord(hostname="api.example.com", source="subfinder"),
        SubdomainRecord(hostname="vpn.example.com", source="amass"),
    ]
    await repo.save_subdomains("scan_sub", records)

    fetched = await repo.get_scan_subdomains("scan_sub")
    assert len(fetched) == 2
    assert {f.hostname for f in fetched} == {"api.example.com", "vpn.example.com"}


@pytest.mark.asyncio
async def test_dns_and_http_crud(repo: ScanRepository) -> None:
    config = ScanConfig(domain="example.com")
    await repo.create_scan("scan_detail", "example.com", config)

    # DNS records
    dns_records = [
        DNSResult(
            hostname="api.example.com",
            is_resolved=True,
            records=[
                DNSRecord(hostname="api.example.com", record_type="A", value="1.1.1.1", ttl=300)
            ],
        ),
        DNSResult(
            hostname="unresolved.example.com",
            is_resolved=False,
            error="NXDOMAIN",
        ),
    ]
    await repo.save_dns_results("scan_detail", dns_records)

    dns_fetched = await repo.get_scan_dns_results("scan_detail")
    assert len(dns_fetched) == 2
    resolved_map = {d.hostname: d.is_resolved for d in dns_fetched}
    assert resolved_map["api.example.com"] is True
    assert resolved_map["unresolved.example.com"] is False

    # HTTP results
    http_records = [
        HTTPResult(
            hostname="api.example.com",
            url="https://api.example.com",
            scheme="https",
            status_code=200,
            response_time_ms=45.2,
            page_title="API Gateway",
        )
    ]
    await repo.save_http_results("scan_detail", http_records)

    http_fetched = await repo.get_scan_http_results("scan_detail")
    assert len(http_fetched) == 1
    assert http_fetched[0].status_code == 200
    assert http_fetched[0].page_title == "API Gateway"


@pytest.mark.asyncio
async def test_full_scan_result_and_delete(repo: ScanRepository) -> None:
    config = ScanConfig(domain="example.com")
    await repo.create_scan("scan_full", "example.com", config)

    sub = SubdomainRecord(hostname="api.example.com", source="subfinder")
    await repo.save_subdomains("scan_full", [sub])

    result = await repo.get_scan_result("scan_full")
    assert result is not None
    assert result.summary.scan_id == "scan_full"
    assert len(result.subdomains) == 1

    # Delete scan
    deleted = await repo.delete_scan("scan_full")
    assert deleted is True

    # Ensure cascade deleted
    subs_after = await repo.get_scan_subdomains("scan_full")
    assert len(subs_after) == 0
