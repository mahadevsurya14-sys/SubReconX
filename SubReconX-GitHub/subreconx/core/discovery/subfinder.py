"""ProjectDiscovery Subfinder discovery engine integration."""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Optional

from subreconx.core.discovery.base import DiscoveryEngine
from subreconx.core.domain_validator import is_valid_hostname
from subreconx.models import SubdomainRecord

logger = logging.getLogger(__name__)


class SubfinderEngine(DiscoveryEngine):
    """Integrates ProjectDiscovery Subfinder for passive subdomain enumeration."""

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout: int = 300,
    ) -> None:
        self._custom_path = binary_path
        self._timeout = timeout
        self._resolved_path: Optional[str] = None

    @property
    def name(self) -> str:
        return "subfinder"

    async def is_available(self) -> bool:
        """Check if subfinder binary is present and executable."""
        binary = self.find_tool("subfinder", self._custom_path)
        if not binary:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode == 0:
                self._resolved_path = binary
                version_str = stdout.decode("utf-8", errors="replace").strip()
                logger.info("Found subfinder at %s (%s)", binary, version_str)
                return True
        except Exception as exc:
            logger.debug("Subfinder availability check failed: %s", exc)

        return False

    async def discover(self, domain: str) -> list[SubdomainRecord]:
        """Run subfinder to passively enumerate subdomains."""
        binary = self._resolved_path or self.find_tool("subfinder", self._custom_path)
        if not binary:
            logger.warning("Subfinder binary not available. Skipping subfinder discovery.")
            return []

        args = [
            binary,
            "-d",
            domain,
            "-silent",
            "-all",
        ]

        logger.info("Executing Subfinder for domain %s (timeout: %ds)", domain, self._timeout)

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
                logger.warning("Subfinder timed out after %d seconds for domain %s", self._timeout, domain)
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return []

            if proc.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                logger.warning("Subfinder returned non-zero exit code %d: %s", proc.returncode, err_msg)

            output = stdout.decode("utf-8", errors="replace")
            now = datetime.now(timezone.utc)

            for line in output.splitlines():
                host = line.strip().lower()
                if not host:
                    continue
                if is_valid_hostname(host):
                    records.append(
                        SubdomainRecord(
                            hostname=host,
                            source=self.name,
                            discovered_at=now,
                        )
                    )

            logger.info("Subfinder discovered %d raw subdomains for %s", len(records), domain)
        except Exception as exc:
            logger.error("Error executing Subfinder on %s: %s", domain, exc)

        return records
