"""Data access repository layer for scans and results."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Optional, Sequence

from subreconx.db.database import Database
from subreconx.models import (
    DNSRecord,
    DNSResult,
    HTTPResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanSummary,
    SubdomainRecord,
)

logger = logging.getLogger(__name__)


class ScanRepository:
    """Handles CRUD operations on scans and discovery results in SQLite."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def create_scan(
        self,
        scan_id: str,
        domain: str,
        config: ScanConfig,
        started_at: Optional[datetime] = None,
    ) -> None:
        """Insert a new scan record."""
        now = (started_at or datetime.now(timezone.utc)).isoformat()
        config_json = config.model_dump_json()

        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO scans (id, domain, status, config_json, started_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, domain, ScanStatus.RUNNING.value, config_json, now),
            )
            await conn.commit()

    async def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        summary: Optional[ScanSummary] = None,
        completed_at: Optional[datetime] = None,
        duration_seconds: Optional[float] = None,
    ) -> None:
        """Update scan status and final summary metrics."""
        summary_json = summary.model_dump_json() if summary else None
        completed_str = completed_at.isoformat() if completed_at else None

        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                UPDATE scans
                SET status = ?, summary_json = coalesce(?, summary_json),
                    completed_at = coalesce(?, completed_at),
                    duration_seconds = coalesce(?, duration_seconds)
                WHERE id = ?
                """,
                (status.value, summary_json, completed_str, duration_seconds, scan_id),
            )
            await conn.commit()

    async def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a scan row by ID."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)

    async def list_scans(self, domain: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
        """List past scans, optionally filtered by domain."""
        async with self.db.get_connection() as conn:
            if domain:
                cursor = await conn.execute(
                    "SELECT * FROM scans WHERE domain = ? ORDER BY started_at DESC LIMIT ?",
                    (domain, limit),
                )
            else:
                cursor = await conn.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                    (limit,),
                )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def save_subdomains(self, scan_id: str, records: Sequence[SubdomainRecord]) -> None:
        """Batch save discovered subdomains."""
        if not records:
            return

        tuples = [
            (
                scan_id,
                r.hostname,
                r.source,
                r.discovered_at.isoformat(),
            )
            for r in records
        ]

        async with self.db.get_connection() as conn:
            await conn.executemany(
                """
                INSERT INTO subdomains (scan_id, hostname, source, discovered_at)
                VALUES (?, ?, ?, ?)
                """,
                tuples,
            )
            await conn.commit()

    async def save_dns_results(self, scan_id: str, results: Sequence[DNSResult]) -> None:
        """Batch save DNS resolution records."""
        if not results:
            return

        tuples: list[tuple[Any, ...]] = []
        for res in results:
            if res.records:
                for rec in res.records:
                    tuples.append(
                        (
                            scan_id,
                            res.hostname,
                            rec.record_type,
                            rec.value,
                            rec.ttl,
                            rec.resolved_at.isoformat(),
                            rec.error,
                        )
                    )
            else:
                # Store unresolved host record with error
                tuples.append(
                    (
                        scan_id,
                        res.hostname,
                        "NONE",
                        "",
                        None,
                        res.resolved_at.isoformat(),
                        res.error or "UNRESOLVED",
                    )
                )

        async with self.db.get_connection() as conn:
            await conn.executemany(
                """
                INSERT INTO dns_records (scan_id, hostname, record_type, value, ttl, resolved_at, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tuples,
            )
            await conn.commit()

    async def save_http_results(self, scan_id: str, results: Sequence[HTTPResult]) -> None:
        """Batch save HTTP probe outcomes."""
        if not results:
            return

        tuples = [
            (
                scan_id,
                r.hostname,
                r.url,
                r.scheme,
                r.status_code,
                r.response_time_ms,
                r.final_url,
                r.page_title,
                r.content_length,
                r.server,
                r.error,
                r.probed_at.isoformat(),
            )
            for r in results
        ]

        async with self.db.get_connection() as conn:
            await conn.executemany(
                """
                INSERT INTO http_results (
                    scan_id, hostname, url, scheme, status_code,
                    response_time_ms, final_url, page_title, content_length,
                    server, error, probed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuples,
            )
            await conn.commit()

    async def get_scan_subdomains(self, scan_id: str) -> list[SubdomainRecord]:
        """Fetch all discovered subdomains for a scan."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT hostname, source, discovered_at FROM subdomains WHERE scan_id = ? ORDER BY hostname ASC",
                (scan_id,),
            )
            rows = await cursor.fetchall()
            return [
                SubdomainRecord(
                    hostname=r["hostname"],
                    source=r["source"],
                    discovered_at=datetime.fromisoformat(r["discovered_at"]),
                    scan_id=scan_id,
                )
                for r in rows
            ]

    async def get_scan_dns_results(self, scan_id: str) -> list[DNSResult]:
        """Fetch all aggregated DNS results for a scan."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM dns_records WHERE scan_id = ? ORDER BY hostname ASC",
                (scan_id,),
            )
            rows = await cursor.fetchall()

        by_host: dict[str, list[DNSRecord]] = {}
        error_by_host: dict[str, Optional[str]] = {}

        for r in rows:
            host = r["hostname"]
            rtype = r["record_type"]
            if host not in by_host:
                by_host[host] = []
                error_by_host[host] = r["error"]

            if rtype != "NONE":
                by_host[host].append(
                    DNSRecord(
                        hostname=host,
                        record_type=rtype,
                        value=r["value"],
                        ttl=r["ttl"],
                        resolved_at=datetime.fromisoformat(r["resolved_at"]),
                        error=r["error"],
                    )
                )

        results: list[DNSResult] = []
        for host, recs in by_host.items():
            is_resolved = len(recs) > 0 and any(
                r.record_type in ("A", "AAAA", "CNAME") for r in recs
            )
            results.append(
                DNSResult(
                    hostname=host,
                    is_resolved=is_resolved,
                    records=recs,
                    error=error_by_host.get(host) if not recs else None,
                )
            )

        return results

    async def get_scan_http_results(self, scan_id: str) -> list[HTTPResult]:
        """Fetch all HTTP probe results for a scan."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM http_results WHERE scan_id = ? ORDER BY hostname ASC, scheme ASC",
                (scan_id,),
            )
            rows = await cursor.fetchall()

            return [
                HTTPResult(
                    hostname=r["hostname"],
                    url=r["url"],
                    scheme=r["scheme"],
                    status_code=r["status_code"],
                    response_time_ms=r["response_time_ms"],
                    final_url=r["final_url"],
                    page_title=r["page_title"],
                    content_length=r["content_length"],
                    server=r["server"],
                    error=r["error"],
                    probed_at=datetime.fromisoformat(r["probed_at"]),
                )
                for r in rows
            ]

    async def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Load the complete ScanResult with all relations."""
        scan_row = await self.get_scan(scan_id)
        if not scan_row:
            return None

        # Build summary
        if scan_row.get("summary_json"):
            summary_data = json.loads(scan_row["summary_json"])
            summary = ScanSummary(**summary_data)
        else:
            started = (
                datetime.fromisoformat(scan_row["started_at"])
                if scan_row.get("started_at")
                else None
            )
            completed = (
                datetime.fromisoformat(scan_row["completed_at"])
                if scan_row.get("completed_at")
                else None
            )
            summary = ScanSummary(
                scan_id=scan_id,
                domain=scan_row["domain"],
                status=ScanStatus(scan_row["status"]),
                started_at=started,
                completed_at=completed,
                duration_seconds=scan_row.get("duration_seconds"),
            )

        subdomains = await self.get_scan_subdomains(scan_id)
        dns_results = await self.get_scan_dns_results(scan_id)
        http_results = await self.get_scan_http_results(scan_id)

        return ScanResult(
            summary=summary,
            subdomains=subdomains,
            dns_results=dns_results,
            http_results=http_results,
        )

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and cascade delete subdomains, dns, and http records."""
        async with self.db.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await conn.commit()
            return cursor.rowcount > 0
