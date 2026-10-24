"""Scope validation and authorization controls.

The ScopeManager ensures that all active interactions (DNS queries,
HTTP probes) target only domains the operator has explicitly authorized.
This is a critical safety boundary.
"""

import logging
from typing import Optional

from subreconx.core.domain_validator import validate_domain, is_valid_hostname
from subreconx.exceptions import ScopeViolationError, InvalidDomainError

logger = logging.getLogger(__name__)


class ScopeManager:
    """Manages the authorized assessment scope.

    All active checks (DNS resolution, HTTP probing) must pass
    scope validation before execution.  This prevents the tool
    from interacting with domains the operator has not authorized.

    Example::

        scope = ScopeManager()
        scope.add_domain("example.com")

        scope.is_in_scope("api.example.com")   # True
        scope.is_in_scope("evil.com")           # False

        # Raises ScopeViolationError:
        scope.validate_target("evil.com")
    """

    def __init__(self) -> None:
        self._authorized_domains: set[str] = set()
        self._wildcard_scopes: set[str] = set()

    # ── Properties ───────────────────────────────────────────────

    @property
    def scopes(self) -> list[str]:
        """Return all authorized scope entries as a sorted list.

        Exact-match domains are listed first, followed by
        wildcard entries in ``*.domain`` notation.
        """
        result: list[str] = []
        for domain in sorted(self._authorized_domains):
            if domain in self._wildcard_scopes:
                result.append(f"*.{domain}")
            else:
                result.append(domain)
        return result

    @property
    def is_empty(self) -> bool:
        """Check whether the scope has any authorized domains."""
        return not self._authorized_domains and not self._wildcard_scopes

    @property
    def domain_count(self) -> int:
        """Return the number of authorized base domains."""
        return len(self._authorized_domains)

    # ── Scope Management ─────────────────────────────────────────

    def add_domain(
        self,
        domain: str,
        include_subdomains: bool = True,
    ) -> str:
        """Add a domain to the authorized scope.

        Args:
            domain: Domain to authorize (will be validated first).
            include_subdomains: If ``True``, all subdomains of this
                domain are also considered in-scope.

        Returns:
            The validated, normalized domain that was added.

        Raises:
            InvalidDomainError: If the domain fails validation.
        """
        validated = validate_domain(domain)

        self._authorized_domains.add(validated)
        if include_subdomains:
            self._wildcard_scopes.add(validated)

        logger.info(
            "Scope updated: added %s (include_subdomains=%s)",
            validated,
            include_subdomains,
        )
        return validated

    def remove_domain(self, domain: str) -> bool:
        """Remove a domain from the authorized scope.

        Args:
            domain: Domain to remove.

        Returns:
            ``True`` if the domain was found and removed.
        """
        domain = domain.lower().strip().rstrip(".")
        removed = False

        if domain in self._authorized_domains:
            self._authorized_domains.discard(domain)
            removed = True
        if domain in self._wildcard_scopes:
            self._wildcard_scopes.discard(domain)
            removed = True

        if removed:
            logger.info("Scope updated: removed %s", domain)
        return removed

    def clear(self) -> None:
        """Remove all domains from the authorized scope."""
        count = len(self._authorized_domains)
        self._authorized_domains.clear()
        self._wildcard_scopes.clear()
        logger.info("Scope cleared (%d domains removed)", count)

    # ── Scope Checking ───────────────────────────────────────────

    def is_in_scope(self, hostname: str) -> bool:
        """Check if a hostname falls within the authorized scope.

        A hostname is in scope if:

        - It exactly matches an authorized domain, **or**
        - It is a subdomain of a wildcard-scoped domain.

        Args:
            hostname: Hostname to check.

        Returns:
            ``True`` if the hostname is in scope.
        """
        if not hostname:
            return False

        hostname = hostname.lower().strip().rstrip(".")

        # Exact match against an authorized domain
        if hostname in self._authorized_domains:
            return True

        # Subdomain match against wildcard scopes
        for scope_domain in self._wildcard_scopes:
            if hostname.endswith(f".{scope_domain}"):
                return True

        return False

    def validate_target(self, hostname: str) -> str:
        """Validate that a hostname is in scope for active checks.

        This should be called before any DNS query or HTTP probe
        to enforce scope restrictions.

        Args:
            hostname: Hostname to validate.

        Returns:
            The normalized hostname.

        Raises:
            InvalidDomainError: If the hostname is syntactically invalid.
            ScopeViolationError: If the hostname is outside the scope.
        """
        if not is_valid_hostname(hostname):
            raise InvalidDomainError(f"Invalid hostname: {hostname!r}")

        hostname = hostname.lower().strip().rstrip(".")

        if not self.is_in_scope(hostname):
            raise ScopeViolationError(
                f"Hostname {hostname!r} is outside the authorized scope. "
                f"Current scope: {self.scopes}"
            )

        logger.debug("Scope check passed: %s", hostname)
        return hostname

    def filter_in_scope(
        self,
        hostnames: list[str],
    ) -> tuple[list[str], list[str]]:
        """Partition hostnames into in-scope and out-of-scope lists.

        Args:
            hostnames: List of hostnames to classify.

        Returns:
            A tuple of ``(in_scope, out_of_scope)`` hostname lists.
        """
        in_scope: list[str] = []
        out_of_scope: list[str] = []

        for hostname in hostnames:
            if self.is_in_scope(hostname):
                in_scope.append(hostname)
            else:
                out_of_scope.append(hostname)

        if out_of_scope:
            logger.warning(
                "Filtered %d out-of-scope hostname(s) out of %d total",
                len(out_of_scope),
                len(hostnames),
            )

        return in_scope, out_of_scope

    # ── Display ──────────────────────────────────────────────────

    def get_scope_display(self) -> str:
        """Get a human-readable scope summary for display before scanning.

        Returns:
            Formatted multi-line string describing the current scope.
        """
        if self.is_empty:
            return "⚠  No domains in scope. Add at least one domain before scanning."

        lines = [
            "╔══════════════════════════════════════════╗",
            "║     Authorized Assessment Scope          ║",
            "╠══════════════════════════════════════════╣",
        ]

        for domain in sorted(self._authorized_domains):
            wildcard = domain in self._wildcard_scopes
            if wildcard:
                lines.append(f"║  *.{domain:<37s}║")
            else:
                lines.append(f"║  {domain:<39s}║")

        lines.append("╚══════════════════════════════════════════╝")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"ScopeManager(domains={sorted(self._authorized_domains)}, "
            f"wildcards={sorted(self._wildcard_scopes)})"
        )
