"""Shared test fixtures for SubReconX."""

import os
from pathlib import Path

import pytest

# Set test environment before any settings import
os.environ["SUBRECONX_DB_PATH"] = "data/test_subreconx.db"
os.environ["SUBRECONX_LOG_LEVEL"] = "DEBUG"
os.environ["SUBRECONX_DEBUG"] = "true"


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Provide a temporary database path."""
    return tmp_path / "test.db"


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    """Reset the settings singleton between tests."""
    from subreconx.config import reset_settings
    reset_settings()
    yield  # type: ignore[misc]
    reset_settings()
