"""Application configuration using pydantic-settings.

Settings are loaded from environment variables prefixed with ``SUBRECONX_``
and optionally from a ``.env`` file in the project root.
"""

import logging
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """SubReconX application settings.

    All fields can be overridden via environment variables
    prefixed with ``SUBRECONX_``. For example::

        export SUBRECONX_LOG_LEVEL=DEBUG
        export SUBRECONX_DNS_TIMEOUT=10.0
    """

    # ── Application ──────────────────────────────────────────────
    app_name: str = "SubReconX"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    # ── Server ───────────────────────────────────────────────────
    host: str = "127.0.0.1"
    port: int = 8000

    # ── Database ─────────────────────────────────────────────────
    db_path: Path = Path("data/subreconx.db")

    # ── DNS Resolution ───────────────────────────────────────────
    dns_resolvers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    )
    dns_timeout: float = 5.0
    dns_concurrency: int = 50

    # ── HTTP/HTTPS Probing ───────────────────────────────────────
    http_timeout: float = 10.0
    http_concurrency: int = 10
    http_rate_limit: float = 20.0  # max requests per second
    http_user_agent: str = "SubReconX/0.1.0 (Security Assessment Tool)"

    # ── External Tools ───────────────────────────────────────────
    subfinder_path: Optional[str] = None  # Auto-detect if None
    amass_path: Optional[str] = None  # Auto-detect if None
    subfinder_timeout: int = 300  # seconds
    amass_timeout: int = 600  # seconds

    # ── Limits ───────────────────────────────────────────────────
    max_subdomains: int = 50_000
    max_scan_history: int = 100

    model_config = {
        "env_prefix": "SUBRECONX_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }

    # ── Validators ───────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log_level is a valid Python logging level name."""
        v = v.upper()
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in valid_levels:
            raise ValueError(
                f"log_level must be one of {sorted(valid_levels)}, got {v!r}"
            )
        return v

    @field_validator("dns_resolvers")
    @classmethod
    def validate_dns_resolvers(cls, v: list[str]) -> list[str]:
        """Require at least one DNS resolver."""
        if not v:
            raise ValueError("At least one DNS resolver is required")
        return v

    @field_validator("http_concurrency")
    @classmethod
    def validate_http_concurrency(cls, v: int) -> int:
        """Cap HTTP concurrency at a safe maximum."""
        if v < 1:
            raise ValueError("http_concurrency must be at least 1")
        if v > 100:
            raise ValueError("http_concurrency must not exceed 100")
        return v

    @field_validator("dns_timeout", "http_timeout")
    @classmethod
    def validate_timeouts(cls, v: float) -> float:
        """Ensure timeouts are positive."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v

    # ── Helpers ──────────────────────────────────────────────────

    def configure_logging(self) -> None:
        """Configure structured application logging."""
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def ensure_directories(self) -> None:
        """Create required data directories if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


# ── Singleton ────────────────────────────────────────────────────

_settings: Optional[Settings] = None


def get_settings(**overrides: object) -> Settings:
    """Get or create the application settings singleton.

    Args:
        **overrides: Keyword arguments forwarded to ``Settings()``
            on first creation only.

    Returns:
        The application ``Settings`` instance.
    """
    global _settings
    if _settings is None:
        _settings = Settings(**overrides)  # type: ignore[arg-type]
    return _settings


def reset_settings() -> None:
    """Reset the settings singleton.  Primarily useful in tests."""
    global _settings
    _settings = None
