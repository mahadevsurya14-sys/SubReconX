"""CSV report generator for SubReconX.

Produces a CSV file (or string) summarising all discovered subdomains
together with their DNS and HTTP probe results.
"""

import csv
import io
import logging
from pathlib import Path
from typing import Optional

from subreconx.models import (
    DNSResult,
    HTTPResult,
    ScanResult,
    SubdomainRecord,
)

logger = logging.getLogger(__name__)


class CSVReportGenerator:
    """Generate CSV reports from :class:`ScanResult` data.

    The output CSV contains one row per discovered subdomain with
    columns covering discovery metadata, DNS resolution, and HTTP
    probe status.
    """

    # Column header names.
    _COLUMNS: list[str] = [
        "hostname",
        "source",
        "discovered_at",
        "dns_resolved",
        "dns_records",
        "http_status",
        "https_status",
        "response_time_ms",
        "page_title",
    ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dns_for_host(
        dns_results: list[DNSResult],
        hostname: str,
    ) -> Optional[DNSResult]:
        """Return the DNSResult for *hostname*, or *None*."""
        for dns in dns_results:
            if dns.hostname == hostname:
                return dns
        return None

    @staticmethod
    def _http_for_host(
        http_results: list[HTTPResult],
        hostname: str,
        scheme: str,
    ) -> Optional[HTTPResult]:
        """Return the HTTPResult for *hostname* + *scheme*, or *None*."""
        for http in http_results:
            if http.hostname == hostname and http.scheme == scheme:
                return http
        return None

    @staticmethod
    def _format_dns_records(dns: Optional[DNSResult]) -> str:
        """Format DNS records as a compact semicolon-separated string."""
        if dns is None or not dns.records:
            return ""
        parts: list[str] = []
        for rec in dns.records:
            parts.append(f"{rec.record_type}:{rec.value}")
        return "; ".join(parts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, result: ScanResult) -> str:
        """Generate a CSV string from a scan result.

        Parameters
        ----------
        result:
            Completed scan result.

        Returns
        -------
        str
            Full CSV content including header comments and data rows.
        """
        buf = io.StringIO()

        # Write metadata header as comment lines.
        summary = result.summary
        buf.write(f"# SubReconX Scan Report\n")
        buf.write(f"# scan_id: {summary.scan_id}\n")
        buf.write(f"# domain: {summary.domain}\n")
        started = (
            summary.started_at.isoformat() if summary.started_at else "N/A"
        )
        buf.write(f"# started_at: {started}\n")
        buf.write(f"# status: {summary.status.value}\n")
        buf.write(f"# total_subdomains: {summary.total_subdomains}\n")
        buf.write(f"#\n")

        writer = csv.writer(buf)
        writer.writerow(self._COLUMNS)

        for sub in result.subdomains:
            dns = self._dns_for_host(result.dns_results, sub.hostname)
            http = self._http_for_host(
                result.http_results, sub.hostname, "http"
            )
            https = self._http_for_host(
                result.http_results, sub.hostname, "https"
            )

            dns_resolved = ""
            if dns is not None:
                dns_resolved = "yes" if dns.is_resolved else "no"

            dns_records_str = self._format_dns_records(dns)

            http_status = (
                str(http.status_code) if http and http.status_code else ""
            )
            https_status = (
                str(https.status_code) if https and https.status_code else ""
            )

            # Prefer HTTPS response time, fall back to HTTP.
            response_time: str = ""
            if https and https.response_time_ms is not None:
                response_time = f"{https.response_time_ms:.1f}"
            elif http and http.response_time_ms is not None:
                response_time = f"{http.response_time_ms:.1f}"

            # Prefer HTTPS page title, fall back to HTTP.
            page_title: str = ""
            if https and https.page_title:
                page_title = https.page_title
            elif http and http.page_title:
                page_title = http.page_title

            writer.writerow(
                [
                    sub.hostname,
                    sub.source,
                    sub.discovered_at.isoformat(),
                    dns_resolved,
                    dns_records_str,
                    http_status,
                    https_status,
                    response_time,
                    page_title,
                ]
            )

        csv_content = buf.getvalue()
        logger.info(
            "Generated CSV report for %s (%d rows)",
            summary.domain,
            len(result.subdomains),
        )
        return csv_content

    def generate_file(
        self,
        result: ScanResult,
        output_path: Path,
    ) -> Path:
        """Write a CSV report to *output_path*.

        Parameters
        ----------
        result:
            Completed scan result.
        output_path:
            Destination file path.

        Returns
        -------
        Path
            The path the file was written to (same as *output_path*).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = self.generate(result)
        output_path.write_text(csv_content, encoding="utf-8")

        logger.info("CSV report written to %s", output_path)
        return output_path
