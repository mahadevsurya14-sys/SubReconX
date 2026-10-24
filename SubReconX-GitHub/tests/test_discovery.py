"""Tests for discovery engine abstractions and integrations."""

from unittest.mock import AsyncMock, patch
import pytest

from subreconx.core.discovery.amass import AmassEngine
from subreconx.core.discovery.base import DiscoveryEngine
from subreconx.core.discovery.subfinder import SubfinderEngine


class DummyEngine(DiscoveryEngine):
    @property
    def name(self) -> str:
        return "dummy"

    async def is_available(self) -> bool:
        return True

    async def discover(self, domain: str):
        return []


def test_find_tool() -> None:
    # Python executable is definitely available
    found = DiscoveryEngine.find_tool("python")
    assert found is not None

    # Completely non-existent binary
    non_existent = DiscoveryEngine.find_tool("definitely_nonexistent_binary_xyz_123")
    assert non_existent is None


@pytest.mark.asyncio
async def test_subfinder_discovery_mocked() -> None:
    engine = SubfinderEngine(timeout=30)

    sample_output = b"api.example.com\nadmin.example.com\n"

    with patch.object(engine, "find_tool", return_value="/mock/bin/subfinder"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (sample_output, b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        records = await engine.discover("example.com")
        assert len(records) == 2
        hostnames = [r.hostname for r in records]
        assert "api.example.com" in hostnames
        assert "admin.example.com" in hostnames
        assert all(r.source == "subfinder" for r in records)


@pytest.mark.asyncio
async def test_amass_discovery_mocked() -> None:
    engine = AmassEngine(timeout=30)

    sample_output = b"portal.example.com\nmail.example.com.\n"

    with patch.object(engine, "find_tool", return_value="/mock/bin/amass"), \
         patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (sample_output, b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        records = await engine.discover("example.com")
        assert len(records) == 2
        hostnames = [r.hostname for r in records]
        assert "portal.example.com" in hostnames
        assert "mail.example.com" in hostnames
        assert all(r.source == "amass" for r in records)
