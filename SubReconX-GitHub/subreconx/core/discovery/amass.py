"""OWASP Amass discovery engine integration (optional)."""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Optional

from subreconx.core.discovery.base import DiscoveryEngine
from subreconx.core.domain_validator import is_valid_hostname
from subreconx.models import SubdomainRecord

logger = logging.getLogger(__name__)


class AmassEngine(DiscoveryEngine):
    """Integrates OWASP Amass for passive enumeration."""

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout: int = 600,
    ) -> None:
        self._custom_path = binary_path
        self._timeout = timeout
        self._resolved_path: Optional[str] = None

    @property
    def name(self) -> str:
        return "amass"

    async def is_available(self) -> bool:
        """Check if amass binary is present and executable."""
        binary = self.find_tool("amass", self._custom_path)
        if not binary:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode == 0:
                self._resolved_path = binary
                version_str = stdout.decode("utf-8", errors="replace").strip()
                logger.info("Found amass at %s (%s)", binary, version_str)
                return True
        except Exception as exc:
            logger.debug("Amass availability check failed: %s", exc)

        return False

    async def discover(self, domain: str) -> list[SubdomainRecord]:
        """Run amass enum passively to collect subdomains."""
        binary = self._resolved_path or self.find_tool("amass", self._custom_path)
        if not binary:
            logger.warning("Amass binary not available. Skipping amass discovery.")
            return []

        args = [
            binary,
            "enum",
            "-passive",
            "-d",
            domain,
        ]

        logger.info("Executing Amass for domain %s (timeout: %ds)", domain, self._timeout)

        records: list[SubdomainRecord] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(self._timeout))
            except asyncio.TimeoutError:
                logger.warning("Amass timed out after %d seconds for domain %s", self._timeout, domain)
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return []

            if proc.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                logger.warning("Amass returned non-zero exit code %d: %s", proc.returncode, err_msg)

            output = stdout.decode("utf-8", errors="replace")
            now = datetime.now(timezone.utc)

            for line in output.splitlines():
                host = line.strip().lower()
                if not host:
                    continue
                # Amass may print FQDN with trailing dot or whitespace
                host = host.rstrip(".")
                if is_valid_hostname(host):
                    records.append(
                        SubdomainRecord(
                            hostname=host,
                            source=self.name,
                            discovered_at=now,
                        )
                    )

            logger.info("Amass discovered %d raw subdomains for %s", len(records), domain)
        except Exception as exc:
            logger.error("Error executing Amass on %s: %s", domain, exc)

        return records
