"""Database schema versioning and migration utility."""

from datetime import datetime, timezone
import logging

from subreconx.db.database import Database

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


async def check_and_migrate(db: Database) -> None:
    """Ensure database schema is up-to-date."""
    await db.init_schema()

    async with db.get_connection() as conn:
        cursor = await conn.execute("SELECT MAX(version) FROM schema_version")
        row = await cursor.fetchone()
        current_version = row[0] if (row and row[0] is not None) else 0

        if current_version < SCHEMA_VERSION:
            logger.info("Migrating database from version %d to %d", current_version, SCHEMA_VERSION)
            now = datetime.now(timezone.utc).isoformat()
            await conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, now),
            )
            await conn.commit()
            logger.info("Database migration to version %d completed", SCHEMA_VERSION)
        else:
            logger.debug("Database schema is current at version %d", current_version)
