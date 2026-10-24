"""Tests for configuration loading and validation."""

import os

import pytest

from subreconx.config import Settings, get_settings, reset_settings


class TestSettings:
    """Test the Settings class directly."""

    def test_default_values(self) -> None:
        """Settings should have sensible defaults."""
        s = Settings()
        assert s.app_name == "SubReconX"
        assert s.host == "127.0.0.1"
        assert s.port == 8000
        assert s.log_level == "DEBUG"  # set in conftest env
        assert len(s.dns_resolvers) >= 1
        assert s.http_concurrency >= 1
        assert s.dns_timeout > 0
        assert s.http_timeout > 0

    def test_log_level_validation_valid(self) -> None:
        """Valid log levels should be accepted and uppercased."""
        for level in ("debug", "INFO", "Warning", "ERROR", "critical"):
            s = Settings(log_level=level)
            assert s.log_level == level.upper()

    def test_log_level_validation_invalid(self) -> None:
        """Invalid log levels should raise ValueError."""
        with pytest.raises(ValueError, match="log_level must be one of"):
            Settings(log_level="VERBOSE")

    def test_empty_dns_resolvers_rejected(self) -> None:
        """An empty resolver list should be rejected."""
        with pytest.raises(ValueError, match="At least one DNS resolver"):
            Settings(dns_resolvers=[])

    def test_http_concurrency_bounds(self) -> None:
        """HTTP concurrency must be between 1 and 100."""
        with pytest.raises(ValueError, match="at least 1"):
            Settings(http_concurrency=0)
        with pytest.raises(ValueError, match="must not exceed 100"):
            Settings(http_concurrency=200)

    def test_negative_timeout_rejected(self) -> None:
        """Negative timeouts should be rejected."""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            Settings(dns_timeout=-1.0)
        with pytest.raises(ValueError, match="Timeout must be positive"):
            Settings(http_timeout=0)

    def test_ensure_directories(self, tmp_path) -> None:
        """ensure_directories should create parent dirs for db_path."""
        db_path = tmp_path / "nested" / "dir" / "test.db"
        s = Settings(db_path=db_path)
        s.ensure_directories()
        assert db_path.parent.exists()

    def test_configure_logging_does_not_raise(self) -> None:
        """configure_logging should not raise."""
        s = Settings()
        s.configure_logging()  # Should succeed without error


class TestSettingsSingleton:
    """Test the get_settings / reset_settings functions."""

    def test_singleton_returns_same_instance(self) -> None:
        """get_settings should return the same object each time."""
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_reset_clears_singleton(self) -> None:
        """reset_settings should allow a new instance to be created."""
        s1 = get_settings()
        reset_settings()
        s2 = get_settings()
        assert s1 is not s2

    def test_env_override(self, monkeypatch) -> None:
        """Environment variables with SUBRECONX_ prefix should override defaults."""
        reset_settings()
        monkeypatch.setenv("SUBRECONX_PORT", "9999")
        monkeypatch.setenv("SUBRECONX_LOG_LEVEL", "WARNING")
        s = get_settings()
        assert s.port == 9999
        assert s.log_level == "WARNING"
