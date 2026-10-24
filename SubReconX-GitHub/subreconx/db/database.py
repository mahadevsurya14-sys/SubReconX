"""SQLite database management using aiosqlite for SubReconX."""

import asyncio
from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import AsyncGenerator, Union

import aiosqlite

logger = logging.getLogger(__name__)

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    config_json TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL,
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_host ON subdomains(hostname);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    resolved_at TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_records(hostname);

CREATE TABLE IF NOT EXISTS http_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    url TEXT NOT NULL,
    scheme TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms REAL,
    final_url TEXT,
    page_title TEXT,
    content_length INTEGER,
    server TEXT,
    error TEXT,
    probed_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_http_scan ON http_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_http_host ON http_results(hostname);
"""


class Database:
    """Manages asynchronous SQLite connection and migrations."""

    def __init__(self, db_path: Union[str, Path]) -> None:
        self.db_path = Path(db_path)
        self._lock = asyncio.Lock()
        self._is_initialized = False

    async def init_schema(self) -> None:
        """Create tables and indexes if they do not exist."""
        async with self._lock:
            if self._is_initialized:
                return

            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            async with aiosqlite.connect(self.db_path) as db:
                await db.executescript(_INIT_SQL)
                await db.commit()

            self._is_initialized = True
            logger.info("Database schema initialized at %s", self.db_path)

    @asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Async context manager yielding an aiosqlite database connection with Row factory."""
        if not self._is_initialized:
            await self.init_schema()

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
