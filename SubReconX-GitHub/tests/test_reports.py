"""Tests for CSV, JSON, and HTML report generators."""

import csv
from datetime import datetime, timezone
import io
import json
import pytest

from subreconx.models import (
    DNSRecord,
    DNSResult,
    HTTPResult,
    ScanResult,
    ScanStatus,
    ScanSummary,
    SubdomainRecord,
)
from subreconx.reporting.csv_report import CSVReportGenerator
from subreconx.reporting.html_report import HTMLReportGenerator
from subreconx.reporting.json_report import JSONReportGenerator


@pytest.fixture
def sample_result() -> ScanResult:
    now = datetime.now(timezone.utc)
    summary = ScanSummary(
        scan_id="test_scan_01",
        domain="example.com",
        status=ScanStatus.COMPLETED,
        total_subdomains=2,
        dns_resolved=1,
        dns_unresolved=1,
        http_live=1,
        started_at=now,
        completed_at=now,
        duration_seconds=1.45,
    )
    subdomains = [
        SubdomainRecord(hostname="api.example.com", source="subfinder", discovered_at=now),
        SubdomainRecord(hostname="dead.example.com", source="manual", discovered_at=now),
    ]
    dns_results = [
        DNSResult(
            hostname="api.example.com",
            is_resolved=True,
            records=[DNSRecord(hostname="api.example.com", record_type="A", value="93.184.216.34")],
        ),
        DNSResult(
            hostname="dead.example.com",
            is_resolved=False,
            error="NXDOMAIN",
        ),
    ]
    http_results = [
        HTTPResult(
            hostname="api.example.com",
            url="https://api.example.com",
            scheme="https",
            status_code=200,
            response_time_ms=85.0,
            page_title="Example API",
        )
    ]
    return ScanResult(
        summary=summary,
        subdomains=subdomains,
        dns_results=dns_results,
        http_results=http_results,
    )


def test_csv_report_generation(sample_result: ScanResult) -> None:
    generator = CSVReportGenerator()
    csv_str = generator.generate(sample_result)

    assert "example.com" in csv_str
    assert "api.example.com" in csv_str
    assert "dead.example.com" in csv_str
    assert "93.184.216.34" in csv_str


def test_json_report_generation(sample_result: ScanResult) -> None:
    generator = JSONReportGenerator()
    json_str = generator.generate(sample_result)

    data = json.loads(json_str)
    assert data["summary"]["domain"] == "example.com"
    assert data["summary"]["scan_id"] == "test_scan_01"
    assert len(data["subdomains"]) == 2


def test_html_report_generation(sample_result: ScanResult) -> None:
    generator = HTMLReportGenerator()
    html_str = generator.generate(sample_result)

    assert "<!DOCTYPE html>" in html_str
    assert "SubReconX" in html_str
    assert "example.com" in html_str
    assert "api.example.com" in html_str
    assert "dead.example.com" in html_str
    assert "RESOLVED" in html_str
    assert "UNRESOLVED" in html_str
