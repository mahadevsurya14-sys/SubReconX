"""DNS resolution and verification engine using dnspython.

Performs asynchronous DNS resolution for A, AAAA, and CNAME records,
detects wildcard DNS behavior, preserves error statuses, and tracks
resolution timestamps.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Optional, Sequence
import uuid

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from subreconx.models import DNSRecord, DNSResult

logger = logging.getLogger(__name__)

# Common record types queried for attack surface mapping
_RECORD_TYPES = [
    dns.rdatatype.A,
    dns.rdatatype.AAAA,
    dns.rdatatype.CNAME,
]


class DNSResolverEngine:
    """Asynchronous DNS verification engine with concurrency and wildcard detection."""

    def __init__(
        self,
        resolvers: Optional[Sequence[str]] = None,
        timeout: float = 5.0,
        concurrency: int = 50,
    ) -> None:
        self._resolvers = list(resolvers) if resolvers else ["8.8.8.8", "1.1.1.1"]
        self._timeout = timeout
        self._concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)

        # Configure dnspython async resolver
        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = self._resolvers
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * 2.0

    async def resolve_hostname(self, hostname: str) -> DNSResult:
        """Resolve DNS records (A, AAAA, CNAME) for a single hostname.

        Args:
            hostname: Target hostname.

        Returns:
            DNSResult with collection of records, resolved status, or error details.
        """
        records: list[DNSRecord] = []
        is_resolved = False
        primary_error: Optional[str] = None
        now = datetime.now(timezone.utc)

        async with self._semaphore:
            for rtype in _RECORD_TYPES:
                rtype_str = dns.rdatatype.to_text(rtype)
                try:
                    answer = await self._resolver.resolve(hostname, rtype)
                    ttl = answer.rrset.ttl if answer.rrset else None

                    for rdata in answer:
                        val = rdata.to_text().rstrip(".")
                        records.append(
                            DNSRecord(
                                hostname=hostname,
                                record_type=rtype_str,
                                value=val,
                                ttl=ttl,
                                resolved_at=now,
                            )
                        )
                    if rtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        is_resolved = True

                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as exc:
                    primary_error = type(exc).__name__
                    # If NXDOMAIN, no need to query other record types
                    break
                except dns.resolver.NoAnswer:
                    # Specific record type has no answer; continue checking other types
                    continue
                except dns.exception.Timeout:
                    primary_error = "DNS_TIMEOUT"
                except Exception as exc:
                    primary_error = f"DNS_ERROR: {type(exc).__name__}"

        # If CNAME was found even without direct A/AAAA, mark as resolved
        if any(r.record_type == "CNAME" for r in records):
            is_resolved = True

        return DNSResult(
            hostname=hostname,
            is_resolved=is_resolved,
            records=records,
            is_wildcard=False,
            error=primary_error if not records else None,
            resolved_at=now,
        )

    async def resolve_batch(self, hostnames: Sequence[str]) -> list[DNSResult]:
        """Resolve a list of hostnames concurrently within concurrency constraints.

        Args:
            hostnames: Hostnames to verify.

        Returns:
            List of DNSResult items corresponding to input hostnames.
        """
        logger.info(
            "Starting DNS verification for %d hostnames (concurrency=%d)",
            len(hostnames),
            self._concurrency,
        )

        tasks = [self.resolve_hostname(host) for host in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        resolved_count = sum(1 for r in results if r.is_resolved)

        logger.info(
            "DNS verification complete: %d/%d resolved",
            resolved_count,
            len(hostnames),
        )
        return list(results)

    async def detect_wildcard(self, domain: str) -> bool:
        """Detect potential wildcard DNS behavior for a base domain.

        Queries a randomized, high-entropy subdomain (e.g. `wildcard-test-<uuid>.<domain>`).
        If it resolves to an IP address, wildcard DNS is likely active.

        Args:
            domain: Base domain to test.

        Returns:
            True if random non-existent subdomain resolves, False otherwise.
        """
        probe_host = f"subreconx-wildcard-{uuid.uuid4().hex[:10]}.{domain}"
        logger.debug("Testing wildcard DNS behavior with %s", probe_host)

        try:
            answer = await self._resolver.resolve(probe_host, dns.rdatatype.A)
            if len(answer) > 0:
                logger.warning("Wildcard DNS detected for domain %s (resolved %s)", domain, probe_host)
                return True
        except Exception:
            # Normal behavior is NXDOMAIN or NoAnswer
            pass

        return False
