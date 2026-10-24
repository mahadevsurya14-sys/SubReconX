"""Abstract base class and utilities for discovery engines."""

from abc import ABC, abstractmethod
import logging
import os
import shutil
from typing import Optional

from subreconx.models import SubdomainRecord

logger = logging.getLogger(__name__)


class DiscoveryEngine(ABC):
    """Abstract base class for external or native discovery tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the discovery engine."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the discovery tool is available on the system."""
        ...

    @abstractmethod
    async def discover(self, domain: str) -> list[SubdomainRecord]:
        """Discover subdomains for the target domain."""
        ...

    @staticmethod
    def find_tool(tool_name: str, custom_path: Optional[str] = None) -> Optional[str]:
        """Locate a binary on the system PATH or custom specified location.

        Args:
            tool_name: Executable name (e.g. 'subfinder' or 'amass').
            custom_path: User-provided absolute or relative path.

        Returns:
            Resolved path to binary, or None if not found.
        """
        if custom_path:
            expanded = os.path.expanduser(os.path.expandvars(custom_path))
            if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
                return os.path.abspath(expanded)
            # On Windows, check with .exe
            if os.name == "nt" and not expanded.endswith(".exe"):
                expanded_exe = f"{expanded}.exe"
                if os.path.isfile(expanded_exe):
                    return os.path.abspath(expanded_exe)
            logger.warning("Custom path specified for %s but not found: %s", tool_name, custom_path)

        resolved = shutil.which(tool_name)
        if resolved:
            return os.path.abspath(resolved)

        return None
