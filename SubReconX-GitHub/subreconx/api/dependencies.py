"""Shared dependency providers for FastAPI routes."""

from typing import Optional

from subreconx.config import get_settings
from subreconx.core.comparator import ScanComparator
from subreconx.core.orchestrator import ScanOrchestrator
from subreconx.db.database import Database
from subreconx.db.repositories import ScanRepository

_db: Optional[Database] = None
_repo: Optional[ScanRepository] = None
_orchestrator: Optional[ScanOrchestrator] = None
_comparator: Optional[ScanComparator] = None


def get_database() -> Database:
    """Get or initialize the Database singleton."""
    global _db
    if _db is None:
        settings = get_settings()
        _db = Database(settings.db_path)
    return _db


def get_repository() -> ScanRepository:
    """Get or initialize the ScanRepository singleton."""
    global _repo
    if _repo is None:
        _repo = ScanRepository(get_database())
    return _repo


def get_orchestrator() -> ScanOrchestrator:
    """Get or initialize the ScanOrchestrator singleton."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator(get_repository())
    return _orchestrator


def get_comparator() -> ScanComparator:
    """Get or initialize the ScanComparator singleton."""
    global _comparator
    if _comparator is None:
        _comparator = ScanComparator()
    return _comparator


def reset_dependencies() -> None:
    """Reset singletons (useful in testing)."""
    global _db, _repo, _orchestrator, _comparator
    _db = None
    _repo = None
    _orchestrator = None
    _comparator = None
