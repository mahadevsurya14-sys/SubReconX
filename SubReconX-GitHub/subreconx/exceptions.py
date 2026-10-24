"""Custom exceptions for SubReconX.

All application-specific exceptions inherit from SubReconXError
to allow broad except clauses when needed while keeping specific
error types for granular handling.
"""


class SubReconXError(Exception):
    """Base exception for all SubReconX errors."""

    def __init__(self, message: str = "", details: str | None = None) -> None:
        self.details = details
        super().__init__(message)


class InvalidDomainError(SubReconXError):
    """Raised when a domain name fails validation."""
    pass


class ScopeViolationError(SubReconXError):
    """Raised when a target is outside the authorized assessment scope."""
    pass


class DiscoveryError(SubReconXError):
    """Raised when subdomain discovery encounters an error."""
    pass


class DNSResolutionError(SubReconXError):
    """Raised when DNS resolution encounters an error."""
    pass


class HTTPProbeError(SubReconXError):
    """Raised when HTTP/HTTPS probing fails."""
    pass


class ToolNotFoundError(SubReconXError):
    """Raised when a required external tool is not installed or not found."""
    pass


class DatabaseError(SubReconXError):
    """Raised when a database operation fails."""
    pass


class ReportGenerationError(SubReconXError):
    """Raised when report generation fails."""
    pass


class ScanCancelledError(SubReconXError):
    """Raised when a scan is cancelled by the operator."""
    pass
