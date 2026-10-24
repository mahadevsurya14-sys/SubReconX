"""FastAPI application factory for SubReconX."""

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from subreconx.api.dependencies import get_database
from subreconx.api.routes import health, reports, results, scans
from subreconx.config import get_settings
from subreconx.db.migrations import check_and_migrate

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_DIR = _BASE_DIR / "static"
_TEMPLATES_DIR = _BASE_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    settings = get_settings()
    settings.configure_logging()
    settings.ensure_directories()

    # Initialize database and run schema migrations
    db = get_database()
    await check_and_migrate(db)

    logger.info("SubReconX v%s initialized successfully", settings.app_version)
    yield
    logger.info("SubReconX shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Advanced Subdomain Discovery & Attack Surface Mapping Platform",
        lifespan=lifespan,
    )

    # CORS middleware (restricted to localhost in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else ["http://127.0.0.1:8000", "http://localhost:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Ensure static and template directories exist
    _STATIC_DIR.mkdir(parents=True, exist_ok=True)
    _TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    # Mount static assets
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Include API routers under /api
    app.include_router(health.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(results.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")

    # Jinja2 template renderer for the UI
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def get_dashboard(request: Request) -> HTMLResponse:
        """Render the primary cybersecurity dashboard."""
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "app_name": settings.app_name,
                "version": settings.app_version,
            },
        )

    return app
