"""Scan orchestration and pipeline controller for SubReconX.

Coordinates discovery, normalization, scope enforcement, DNS verification,
HTTP probing, and database persistence.
"""

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Optional

from subreconx.config import get_settings
from subreconx.core.discovery.amass import AmassEngine
from subreconx.core.discovery.subfinder import SubfinderEngine
from subreconx.core.dns_resolver import DNSResolverEngine
from subreconx.core.domain_validator import validate_domain
from subreconx.core.http_prober import HTTPProber
from subreconx.core.normalizer import normalize_and_deduplicate
from subreconx.core.scope import ScopeManager
from subreconx.db.repositories import ScanRepository
from subreconx.exceptions import ScanCancelledError, ScopeViolationError
from subreconx.models import (
    DNSResult,
    HTTPResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanSummary,
    SubdomainRecord,
)

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates end-to-end subdomain enumeration and attack surface mapping."""

    def __init__(self, repository: ScanRepository) -> None:
        self.repository = repository
        self.settings = get_settings()
        self._active_scans: dict[str, ScanStatus] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._scan_tasks: dict[str, asyncio.Task] = {}

    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Return the in-memory or database status of a scan."""
        return self._active_scans.get(scan_id)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Request cancellation of an in-progress scan."""
        if scan_id in self._cancel_events:
            logger.info("Signalling cancellation for scan %s", scan_id)
            self._cancel_events[scan_id].set()
            task = self._scan_tasks.get(scan_id)
            if task and not task.done():
                task.cancel()
            self._active_scans[scan_id] = ScanStatus.CANCELLED
            await self.repository.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.CANCELLED,
            )
            return True
        return False

    async def run_scan(self, config: ScanConfig, scan_id: Optional[str] = None) -> ScanResult:
        """Execute a full scan pipeline.

        1. Scope and domain validation
        2. Passive enumeration (Subfinder / Amass)
        3. Normalization and deduplication
        4. DNS resolution & wildcard detection (optional)
        5. HTTP/HTTPS probing (optional)
        6. Result consolidation and persistence
        """
        # Validate domain input
        domain = validate_domain(config.domain)
        scan_id = scan_id or ScanSummary(domain=domain).scan_id

        cancel_event = asyncio.Event()
        self._cancel_events[scan_id] = cancel_event
        self._active_scans[scan_id] = ScanStatus.RUNNING

        started_at = datetime.now(timezone.utc)
        start_time = time.monotonic()

        # Initialize scope manager
        scope = ScopeManager()
        scope.add_domain(domain, include_subdomains=True)

        logger.info("Initialized scan %s for target %s", scan_id, domain)
        await self.repository.create_scan(
            scan_id=scan_id,
            domain=domain,
            config=config,
            started_at=started_at,
        )

        errors: list[str] = []
        warnings: list[str] = []
        sources_used: list[str] = []
        raw_subdomains: list[SubdomainRecord] = []
        dns_results: list[DNSResult] = []
        http_results: list[HTTPResult] = []

        try:
            # ── 1. Discovery Phase ───────────────────────────────────
            if cancel_event.is_set():
                raise ScanCancelledError("Scan cancelled before discovery")

            # Always add base domain as discovered asset
            raw_subdomains.append(
                SubdomainRecord(
                    hostname=domain,
                    source="base_target",
                    discovered_at=started_at,
                    scan_id=scan_id,
                )
            )

            # Subfinder discovery
            if config.use_subfinder:
                subfinder = SubfinderEngine(
                    binary_path=self.settings.subfinder_path,
                    timeout=self.settings.subfinder_timeout,
                )
                if await subfinder.is_available():
                    sources_used.append("subfinder")
                    found = await subfinder.discover(domain)
                    for r in found:
                        r.scan_id = scan_id
                    raw_subdomains.extend(found)
                else:
                    warnings.append("Subfinder binary not available on system")

            # Amass discovery
            if config.use_amass:
                amass = AmassEngine(
                    binary_path=self.settings.amass_path,
                    timeout=self.settings.amass_timeout,
                )
                if await amass.is_available():
                    sources_used.append("amass")
                    found = await amass.discover(domain)
                    for r in found:
                        r.scan_id = scan_id
                    raw_subdomains.extend(found)
                else:
                    warnings.append("Amass binary not available on system")

            if cancel_event.is_set():
                raise ScanCancelledError("Scan cancelled after discovery")

            # ── 2. Normalization & Scope Enforcement ─────────────────
            normalized_records = normalize_and_deduplicate(raw_subdomains)
            for r in normalized_records:
                r.scan_id = scan_id

            # Filter in-scope targets
            candidate_hosts = [r.hostname for r in normalized_records]
            in_scope_hosts, out_of_scope_hosts = scope.filter_in_scope(candidate_hosts)

            if out_of_scope_hosts:
                warnings.append(f"Ignored {len(out_of_scope_hosts)} out-of-scope hostnames")

            in_scope_set = set(in_scope_hosts)
            subdomains = [r for r in normalized_records if r.hostname in in_scope_set]

            # Save discovered subdomains to database
            await self.repository.save_subdomains(scan_id, subdomains)

            # ── 3. DNS Verification Phase ────────────────────────────
            if cancel_event.is_set():
                raise ScanCancelledError("Scan cancelled before DNS verification")

            dns_resolved_count = 0
            dns_unresolved_count = 0

            if config.enable_dns and in_scope_hosts:
                dns_resolver = DNSResolverEngine(
                    resolvers=config.dns_resolvers or self.settings.dns_resolvers,
                    timeout=config.dns_timeout or self.settings.dns_timeout,
                    concurrency=self.settings.dns_concurrency,
                )

                # Check wildcard
                is_wildcard = await dns_resolver.detect_wildcard(domain)
                if is_wildcard:
                    warnings.append(f"Possible DNS wildcard active on {domain}")

                dns_results = await dns_resolver.resolve_batch(in_scope_hosts)
                for res in dns_results:
                    if is_wildcard:
                        res.is_wildcard = True
                    if res.is_resolved:
                        dns_resolved_count += 1
                    else:
                        dns_unresolved_count += 1

                await self.repository.save_dns_results(scan_id, dns_results)

            # ── 4. HTTP/HTTPS Probing Phase ──────────────────────────
            if cancel_event.is_set():
                raise ScanCancelledError("Scan cancelled before HTTP probing")

            http_live_count = 0
            https_live_count = 0

            if config.enable_http:
                # Target resolved hosts, or all in-scope if DNS was disabled
                if config.enable_dns:
                    probe_targets = [r.hostname for r in dns_results if r.is_resolved]
                else:
                    probe_targets = in_scope_hosts

                if probe_targets:
                    prober = HTTPProber(
                        timeout=config.http_timeout or self.settings.http_timeout,
                        concurrency=config.http_concurrency or self.settings.http_concurrency,
                        rate_limit=self.settings.http_rate_limit,
                        user_agent=self.settings.http_user_agent,
                    )
                    try:
                        http_results = await prober.probe_batch(probe_targets)
                        await self.repository.save_http_results(scan_id, http_results)

                        for h in http_results:
                            if h.is_live:
                                if h.scheme == "https":
                                    https_live_count += 1
                                else:
                                    http_live_count += 1
                    finally:
                        await prober.close()

            # ── 5. Completion & Metrics ──────────────────────────────
            completed_at = datetime.now(timezone.utc)
            duration_seconds = time.monotonic() - start_time

            summary = ScanSummary(
                scan_id=scan_id,
                domain=domain,
                status=ScanStatus.COMPLETED,
                total_subdomains=len(subdomains),
                dns_resolved=dns_resolved_count,
                dns_unresolved=dns_unresolved_count,
                http_live=http_live_count,
                https_live=https_live_count,
                sources_used=sources_used,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration_seconds,
                errors=errors,
                warnings=warnings,
            )

            await self.repository.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                summary=summary,
                completed_at=completed_at,
                duration_seconds=duration_seconds,
            )
            self._active_scans[scan_id] = ScanStatus.COMPLETED

            logger.info(
                "Scan %s for %s finished successfully in %.2fs: %d subdomains",
                scan_id,
                domain,
                duration_seconds,
                len(subdomains),
            )

            return ScanResult(
                summary=summary,
                subdomains=subdomains,
                dns_results=dns_results,
                http_results=http_results,
            )

        except asyncio.CancelledError:
            logger.info("Scan %s task was cancelled", scan_id)
            self._active_scans[scan_id] = ScanStatus.CANCELLED
            await self.repository.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.CANCELLED,
            )
            raise
        except ScanCancelledError:
            logger.info("Scan %s was cancelled by operator", scan_id)
            self._active_scans[scan_id] = ScanStatus.CANCELLED
            await self.repository.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.CANCELLED,
            )
            raise
        except Exception as exc:
            logger.error("Scan %s failed: %s", scan_id, exc, exc_info=True)
            self._active_scans[scan_id] = ScanStatus.FAILED
            errors.append(str(exc))
            fail_summary = ScanSummary(
                scan_id=scan_id,
                domain=domain,
                status=ScanStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=time.monotonic() - start_time,
                errors=errors,
                warnings=warnings,
            )
            await self.repository.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                summary=fail_summary,
            )
            raise
        finally:
            self._cancel_events.pop(scan_id, None)
            self._scan_tasks.pop(scan_id, None)
