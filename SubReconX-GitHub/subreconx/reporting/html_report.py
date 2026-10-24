"""HTML report generator for SubReconX.

Produces a self-contained HTML report with inline CSS using a Jinja2
template.  The report features a dark cybersecurity-themed design with
green accents, summary metric cards, and a detailed subdomains table.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from subreconx.models import DNSResult, HTTPResult, ScanResult

logger = logging.getLogger(__name__)

# Path to the ``templates/`` directory relative to the package root.
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class HTMLReportGenerator:
    """Generate professional HTML reports from :class:`ScanResult` data.

    The output is a single, self-contained HTML file with all styles
    inlined – no external CSS, JS, or image dependencies.
    """

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dns_for_host(
        dns_results: list[DNSResult],
        hostname: str,
    ) -> Optional[DNSResult]:
        """Return the :class:`DNSResult` for *hostname*, or *None*."""
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
        """Return the :class:`HTTPResult` matching *hostname* + *scheme*."""
        for http in http_results:
            if http.hostname == hostname and http.scheme == scheme:
                return http
        return None

    @staticmethod
    def _format_dns_records(dns: Optional[DNSResult]) -> str:
        """Compact DNS record summary string."""
        if dns is None or not dns.records:
            return "—"
        parts: list[str] = []
        for rec in dns.records:
            parts.append(f"{rec.record_type}: {rec.value}")
        return "; ".join(parts)

    @staticmethod
    def _http_status_label(
        http: Optional[HTTPResult],
    ) -> str:
        """Human-friendly HTTP status string."""
        if http is None:
            return "—"
        if http.error:
            return f"Error"
        if http.status_code is not None:
            return str(http.status_code)
        return "—"

    @staticmethod
    def _http_status_class(
        http: Optional[HTTPResult],
    ) -> str:
        """CSS class for status badge colouring."""
        if http is None or http.status_code is None:
            return "status-unknown"
        code = http.status_code
        if 200 <= code < 300:
            return "status-ok"
        if 300 <= code < 400:
            return "status-redirect"
        if 400 <= code < 500:
            return "status-client-err"
        return "status-server-err"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, result: ScanResult) -> str:
        """Render the HTML report from *result*.

        Parameters
        ----------
        result:
            Completed scan result.

        Returns
        -------
        str
            Complete HTML document as a string.
        """
        summary = result.summary

        # Pre-compute per-row data for the template.
        rows: list[dict] = []
        for sub in result.subdomains:
            dns = self._dns_for_host(result.dns_results, sub.hostname)
            http = self._http_for_host(
                result.http_results, sub.hostname, "http"
            )
            https = self._http_for_host(
                result.http_results, sub.hostname, "https"
            )

            # Pick best response time (prefer HTTPS).
            response_time: str = "—"
            if https and https.response_time_ms is not None:
                response_time = f"{https.response_time_ms:.0f} ms"
            elif http and http.response_time_ms is not None:
                response_time = f"{http.response_time_ms:.0f} ms"

            rows.append(
                {
                    "hostname": sub.hostname,
                    "source": sub.source,
                    "dns_resolved": (
                        dns.is_resolved if dns is not None else None
                    ),
                    "dns_records": self._format_dns_records(dns),
                    "http_status": self._http_status_label(http),
                    "http_class": self._http_status_class(http),
                    "https_status": self._http_status_label(https),
                    "https_class": self._http_status_class(https),
                    "response_time": response_time,
                }
            )

        # Compute summary stats.
        http_live = sum(1 for r in result.http_results if r.is_live)
        dns_resolved = sum(
            1 for d in result.dns_results if d.is_resolved
        )
        dns_unresolved = len(result.dns_results) - dns_resolved

        template = self._env.get_template("report.html")
        html = template.render(
            summary=summary,
            rows=rows,
            total_subdomains=len(result.subdomains),
            dns_resolved=dns_resolved,
            dns_unresolved=dns_unresolved,
            http_live=http_live,
            generated_at=datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
        )

        logger.info(
            "Generated HTML report for %s (%d bytes)",
            summary.domain,
            len(html),
        )
        return html

    def generate_file(
        self,
        result: ScanResult,
        output_path: Path,
    ) -> Path:
        """Write the HTML report to *output_path*.

        Parameters
        ----------
        result:
            Completed scan result.
        output_path:
            Destination file path.

        Returns
        -------
        Path
            The path the file was written to.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html_content = self.generate(result)
        output_path.write_text(html_content, encoding="utf-8")

        logger.info("HTML report written to %s", output_path)
        return output_path
