"""Health and environment diagnostics route."""

from fastapi import APIRouter
import shutil

from subreconx.config import get_settings

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
async def get_health() -> dict:
    """Return health status and external tool availability."""
    settings = get_settings()
    subfinder_avail = shutil.which("subfinder") is not None
    amass_avail = shutil.which("amass") is not None

    return {
        "status": "healthy",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "tools": {
            "subfinder": {
                "installed": subfinder_avail,
                "path": shutil.which("subfinder"),
            },
            "amass": {
                "installed": amass_avail,
                "path": shutil.which("amass"),
            },
        },
    }
