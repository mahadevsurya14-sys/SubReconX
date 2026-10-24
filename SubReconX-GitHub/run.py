"""SubReconX entry point.

Usage::

    python run.py
    # or with uvicorn directly:
    uvicorn subreconx.api.app:create_app --factory --host 127.0.0.1 --port 8000
"""

import sys


def main() -> None:
    """Start the SubReconX application."""
    try:
        import uvicorn
        from subreconx.config import get_settings

        settings = get_settings()
        settings.configure_logging()
        settings.ensure_directories()

        print(
            f"\n"
            f"  ╔═══════════════════════════════════════╗\n"
            f"  ║         SubReconX  v{settings.app_version:<17s}║\n"
            f"  ║  Subdomain Discovery & Attack Surface ║\n"
            f"  ║         Mapping Platform               ║\n"
            f"  ╚═══════════════════════════════════════╝\n"
            f"\n"
            f"  ➜  Dashboard: http://{settings.host}:{settings.port}\n"
            f"  ➜  API Docs:  http://{settings.host}:{settings.port}/docs\n"
        )

        uvicorn.run(
            "subreconx.api.app:create_app",
            factory=True,
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            log_level=settings.log_level.lower(),
        )
    except KeyboardInterrupt:
        print("\n  ✖  Shutting down SubReconX...")
        sys.exit(0)
    except ImportError as exc:
        print(
            f"\n  ✖  Missing dependency: {exc}\n"
            f"  Run: pip install -r requirements.txt\n",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
