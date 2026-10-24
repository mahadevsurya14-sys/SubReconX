"""Historical scan comparison engine for SubReconX.

Compares two :class:`ScanResult` instances (old vs. new) and produces a
:class:`ScanComparison` that highlights newly-appeared subdomains, removed
subdomains, and changes in DNS resolution status.
"""

import logging

from subreconx.models import ScanComparison, ScanResult

logger = logging.getLogger(__name__)


class ScanComparator:
    """Compare two scan results for the same domain.

    Usage::

        comparator = ScanComparator()
        diff = comparator.compare(old_scan, new_scan)
        print(diff.new_subdomains)
    """

    def compare(
        self,
        old_result: ScanResult,
        new_result: ScanResult,
    ) -> ScanComparison:
        """Produce a diff between *old_result* and *new_result*.

        Parameters
        ----------
        old_result:
            The baseline (earlier) scan result.
        new_result:
            The current (later) scan result.

        Returns
        -------
        ScanComparison
            Model containing new, removed, and unchanged subdomains as
            well as newly-resolved / newly-unresolved hostname lists.
        """
        domain = new_result.summary.domain

        # -- Subdomain hostname sets -----------------------------------------
        old_hostnames: set[str] = {
            rec.hostname for rec in old_result.subdomains
        }
        new_hostnames: set[str] = {
            rec.hostname for rec in new_result.subdomains
        }

        new_subs = sorted(new_hostnames - old_hostnames)
        removed_subs = sorted(old_hostnames - new_hostnames)
        unchanged_subs = sorted(old_hostnames & new_hostnames)

        # -- DNS resolution delta --------------------------------------------
        old_resolved: set[str] = {
            dns.hostname
            for dns in old_result.dns_results
            if dns.is_resolved
        }
        new_resolved: set[str] = {
            dns.hostname
            for dns in new_result.dns_results
            if dns.is_resolved
        }

        # Resolved in new but not in old.
        newly_resolved = sorted(new_resolved - old_resolved)
        # Was resolved in old but no longer resolved in new.
        newly_unresolved = sorted(old_resolved - new_resolved)

        comparison = ScanComparison(
            domain=domain,
            scan_id_old=old_result.summary.scan_id,
            scan_id_new=new_result.summary.scan_id,
            new_subdomains=new_subs,
            removed_subdomains=removed_subs,
            unchanged_subdomains=unchanged_subs,
            newly_resolved=newly_resolved,
            newly_unresolved=newly_unresolved,
        )

        logger.info(
            "Comparison %s vs %s: +%d -%d ~%d subdomains, "
            "+%d resolved, -%d unresolved",
            comparison.scan_id_old,
            comparison.scan_id_new,
            len(new_subs),
            len(removed_subs),
            len(unchanged_subs),
            len(newly_resolved),
            len(newly_unresolved),
        )

        return comparison
