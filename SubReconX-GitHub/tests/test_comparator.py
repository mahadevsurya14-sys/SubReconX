"""Tests for historical scan comparison."""

from datetime import datetime, timezone
import pytest

from subreconx.core.comparator import ScanComparator
from subreconx.models import (
    DNSRecord,
    DNSResult,
    ScanResult,
    ScanStatus,
    ScanSummary,
    SubdomainRecord,
)


@pytest.fixture
def make_scan_result():
    def _maker(scan_id: str, hosts: list[str], resolved_hosts: list[str]) -> ScanResult:
        now = datetime.now(timezone.utc)
        subdomains = [
            SubdomainRecord(hostname=h, source="subfinder", discovered_at=now, scan_id=scan_id)
            for h in hosts
        ]
        dns_results = [
            DNSResult(
                hostname=h,
                is_resolved=h in resolved_hosts,
                records=[DNSRecord(hostname=h, record_type="A", value="1.2.3.4")]
                if h in resolved_hosts
                else [],
            )
            for h in hosts
        ]
        summary = ScanSummary(
            scan_id=scan_id,
            domain="example.com",
            status=ScanStatus.COMPLETED,
            total_subdomains=len(hosts),
            dns_resolved=len(resolved_hosts),
        )
        return ScanResult(
            summary=summary,
            subdomains=subdomains,
            dns_results=dns_results,
            http_results=[],
        )

    return _maker


def test_scan_comparison(make_scan_result) -> None:
    old_scan = make_scan_result(
        "scan-1",
        hosts=["api.example.com", "dev.example.com", "old.example.com"],
        resolved_hosts=["api.example.com", "dev.example.com"],
    )

    new_scan = make_scan_result(
        "scan-2",
        hosts=["api.example.com", "dev.example.com", "new.example.com"],
        resolved_hosts=["api.example.com", "new.example.com"],
    )

    comparator = ScanComparator()
    diff = comparator.compare(old_scan, new_scan)

    assert diff.domain == "example.com"
    assert diff.scan_id_old == "scan-1"
    assert diff.scan_id_new == "scan-2"

    assert diff.new_subdomains == ["new.example.com"]
    assert diff.removed_subdomains == ["old.example.com"]
    assert sorted(diff.unchanged_subdomains) == ["api.example.com", "dev.example.com"]

    assert diff.newly_resolved == ["new.example.com"]
    assert diff.newly_unresolved == ["dev.example.com"]
