"""Pydantic models and data structures for SubReconX.

These models define the core data types used throughout the application
for scan configuration, results, and reporting.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _new_scan_id() -> str:
    """Generate a unique scan identifier."""
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScanStatus(str, enum.Enum):
    """Status of a scan lifecycle."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoverySource(str, enum.Enum):
    """Source that discovered a subdomain."""
    SUBFINDER = "subfinder"
    AMASS = "amass"
    MANUAL = "manual"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Scan Configuration
# ---------------------------------------------------------------------------

class ScanConfig(BaseModel):
    """Configuration for a single scan run."""
    domain: str
    enable_dns: bool = True
    enable_http: bool = False
    dns_resolvers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1"]
    )
    dns_timeout: float = 5.0
    http_timeout: float = 10.0
    http_concurrency: int = 10
    use_subfinder: bool = True
    use_amass: bool = False


# ---------------------------------------------------------------------------
# Discovery Results
# ---------------------------------------------------------------------------

class SubdomainRecord(BaseModel):
    """A single discovered subdomain entry."""
    hostname: str
    source: str = "unknown"
    discovered_at: datetime = Field(default_factory=_utcnow)
    scan_id: Optional[str] = None

    def __hash__(self) -> int:
        return hash(self.hostname)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SubdomainRecord):
            return self.hostname == other.hostname
        return NotImplemented


# ---------------------------------------------------------------------------
# DNS Results
# ---------------------------------------------------------------------------

class DNSRecord(BaseModel):
    """DNS resolution result for a single record."""
    hostname: str
    record_type: str  # A, AAAA, CNAME, MX, TXT, NS, etc.
    value: str
    ttl: Optional[int] = None
    resolved_at: datetime = Field(default_factory=_utcnow)
    error: Optional[str] = None


class DNSResult(BaseModel):
    """Aggregated DNS result for a hostname."""
    hostname: str
    is_resolved: bool = False
    records: list[DNSRecord] = Field(default_factory=list)
    is_wildcard: bool = False
    error: Optional[str] = None
    resolved_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# HTTP/HTTPS Results
# ---------------------------------------------------------------------------

class HTTPResult(BaseModel):
    """HTTP or HTTPS probe result for a single URL."""
    hostname: str
    url: str
    scheme: str  # "http" or "https"
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    final_url: Optional[str] = None
    page_title: Optional[str] = None
    content_length: Optional[int] = None
    server: Optional[str] = None
    error: Optional[str] = None
    probed_at: datetime = Field(default_factory=_utcnow)

    @property
    def is_live(self) -> bool:
        """Whether the probe received a valid HTTP response."""
        return self.status_code is not None and self.error is None


# ---------------------------------------------------------------------------
# Scan Summary & Results
# ---------------------------------------------------------------------------

class ScanSummary(BaseModel):
    """Summary statistics for a completed or in-progress scan."""
    scan_id: str = Field(default_factory=_new_scan_id)
    domain: str
    status: ScanStatus = ScanStatus.PENDING
    total_subdomains: int = 0
    dns_resolved: int = 0
    dns_unresolved: int = 0
    http_live: int = 0
    https_live: int = 0
    sources_used: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete scan result containing all data."""
    summary: ScanSummary
    subdomains: list[SubdomainRecord] = Field(default_factory=list)
    dns_results: list[DNSResult] = Field(default_factory=list)
    http_results: list[HTTPResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Historical Comparison
# ---------------------------------------------------------------------------

class ScanComparison(BaseModel):
    """Comparison between two scans of the same domain."""
    domain: str
    scan_id_old: str
    scan_id_new: str
    new_subdomains: list[str] = Field(default_factory=list)
    removed_subdomains: list[str] = Field(default_factory=list)
    unchanged_subdomains: list[str] = Field(default_factory=list)
    newly_resolved: list[str] = Field(default_factory=list)
    newly_unresolved: list[str] = Field(default_factory=list)
    compared_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# API Request / Response Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """API request to start a new scan."""
    domain: str
    enable_dns: bool = True
    enable_http: bool = False
    use_subfinder: bool = True
    use_amass: bool = False


class ScanStatusResponse(BaseModel):
    """API response for scan status queries."""
    scan_id: str
    domain: str
    status: ScanStatus
    progress: Optional[str] = None
    summary: Optional[ScanSummary] = None


class ErrorResponse(BaseModel):
    """Standard API error response."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None
