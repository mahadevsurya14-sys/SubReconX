"""Hostname normalization and deduplication for SubReconX.

Provides functions to clean raw hostnames, remove duplicates, and merge
discovery source metadata.
"""

import logging
from typing import Sequence

from subreconx.core.domain_validator import is_valid_hostname
from subreconx.models import SubdomainRecord

logger = logging.getLogger(__name__)


def normalize_hostname(hostname: str) -> str:
    """Normalize a raw hostname string.

    Lowercases, strips leading/trailing whitespace, removes trailing FQDN dots,
    and strips leading wildcard markers (e.g. `*.`). Returns empty string if invalid.

    Args:
        hostname: Raw hostname string.

    Returns:
        Cleaned, normalized hostname, or empty string if not valid.
    """
    if not hostname or not isinstance(hostname, str):
        return ""

    cleaned = hostname.strip().lower()

    # Remove protocol prefix if accidentally included
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]

    # Remove port or path if present
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]

    # Remove leading wildcard
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    elif cleaned.startswith("."):
        cleaned = cleaned.lstrip(".")

    # Remove trailing dot
    cleaned = cleaned.rstrip(".")

    if not is_valid_hostname(cleaned):
        return ""

    return cleaned


def deduplicate_subdomains(records: Sequence[SubdomainRecord]) -> list[SubdomainRecord]:
    """Deduplicate subdomain records while preserving order.

    The first occurrence of each unique hostname is preserved.

    Args:
        records: List of SubdomainRecord instances.

    Returns:
        Deduplicated list of SubdomainRecord instances.
    """
    seen: set[str] = set()
    deduped: list[SubdomainRecord] = []

    for record in records:
        norm = normalize_hostname(record.hostname)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        # Ensure record has normalized hostname
        if record.hostname != norm:
            record = record.model_copy(update={"hostname": norm})
        deduped.append(record)

    logger.debug(
        "Deduplication: %d input records -> %d unique records",
        len(records),
        len(deduped),
    )
    return deduped


def merge_sources(records: Sequence[SubdomainRecord]) -> dict[str, SubdomainRecord]:
    """Group subdomain records by hostname and merge their discovery sources.

    Args:
        records: List of SubdomainRecord instances.

    Returns:
        Dictionary mapping normalized hostname to SubdomainRecord with merged sources.
    """
    merged: dict[str, SubdomainRecord] = {}
    sources_per_host: dict[str, set[str]] = {}

    for record in records:
        norm = normalize_hostname(record.hostname)
        if not norm:
            continue

        raw_sources = {s.strip() for s in record.source.split(",") if s.strip()}
        if norm not in merged:
            merged[norm] = record.model_copy(update={"hostname": norm})
            sources_per_host[norm] = set(raw_sources)
        else:
            sources_per_host[norm].update(raw_sources)
            # Keep earliest discovery time
            if record.discovered_at < merged[norm].discovered_at:
                merged[norm] = merged[norm].model_copy(
                    update={"discovered_at": record.discovered_at}
                )

    # Update merged sources string
    for host, host_sources in sources_per_host.items():
        sorted_sources = ",".join(sorted(host_sources))
        merged[host] = merged[host].model_copy(update={"source": sorted_sources})

    return merged


def normalize_and_deduplicate(records: Sequence[SubdomainRecord]) -> list[SubdomainRecord]:
    """Full normalization and deduplication pipeline.

    Normalizes all hostnames, filters invalid entries, merges multiple source
    attributions, and returns sorted unique records.

    Args:
        records: Collection of discovered SubdomainRecord items.

    Returns:
        Clean, deduplicated, source-merged list of SubdomainRecord items.
    """
    merged_map = merge_sources(records)
    # Sort alphabetically by hostname
    return sorted(merged_map.values(), key=lambda r: r.hostname)
