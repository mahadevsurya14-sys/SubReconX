"""JSON report generator for SubReconX.

Produces a pretty-printed JSON document containing the full scan result
with all subdomains, DNS records, and HTTP probe results grouped by
hostname for easy consumption by downstream tools.
"""

import json
import logging
from pathlib import Path

from subreconx.models import ScanResult

logger = logging.getLogger(__name__)


class JSONReportGenerator:
    """Generate JSON reports from :class:`ScanResult` data.

    The output JSON preserves the full Pydantic model structure with
    human-readable formatting and ISO-8601 datetime serialisation.
    """

    def generate(self, result: ScanResult) -> str:
        """Generate a pretty-printed JSON string from a scan result.

        The output groups DNS and HTTP results under each hostname for
        easier reading while also preserving the raw flat lists.

        Parameters
        ----------
        result:
            Completed scan result.

        Returns
        -------
        str
            JSON-encoded string with 2-space indentation.
        """
        # Serialise via Pydantic with mode="json" so datetimes become
        # ISO-8601 strings and enums become their values.
        raw: dict = result.model_dump(mode="json")

        # Build an additional ``by_hostname`` index for convenience.
        dns_by_host: dict[str, list[dict]] = {}
        for dns_entry in raw.get("dns_results", []):
            host = dns_entry.get("hostname", "")
            dns_by_host.setdefault(host, []).append(dns_entry)

        http_by_host: dict[str, list[dict]] = {}
        for http_entry in raw.get("http_results", []):
            host = http_entry.get("hostname", "")
            http_by_host.setdefault(host, []).append(http_entry)

        by_hostname: dict[str, dict] = {}
        for sub in raw.get("subdomains", []):
            host = sub.get("hostname", "")
            by_hostname[host] = {
                "subdomain": sub,
                "dns": dns_by_host.get(host, []),
                "http": http_by_host.get(host, []),
            }

        report: dict = {
            "meta": {
                "generator": "SubReconX",
                "version": "0.1.0",
            },
            "summary": raw.get("summary", {}),
            "subdomains": raw.get("subdomains", []),
            "dns_results": raw.get("dns_results", []),
            "http_results": raw.get("http_results", []),
            "by_hostname": by_hostname,
        }

        json_str = json.dumps(report, indent=2, ensure_ascii=False)

        logger.info(
            "Generated JSON report for %s (%d bytes)",
            result.summary.domain,
            len(json_str),
        )
        return json_str

    def generate_file(
        self,
        result: ScanResult,
        output_path: Path,
    ) -> Path:
        """Write a JSON report to *output_path*.

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

        json_content = self.generate(result)
        output_path.write_text(json_content, encoding="utf-8")

        logger.info("JSON report written to %s", output_path)
        return output_path
