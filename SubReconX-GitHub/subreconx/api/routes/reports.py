"""Report export API routes."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status

from subreconx.api.dependencies import get_repository
from subreconx.db.repositories import ScanRepository
from subreconx.models import ScanResult
from subreconx.reporting.csv_report import CSVReportGenerator
from subreconx.reporting.html_report import HTMLReportGenerator
from subreconx.reporting.json_report import JSONReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{scan_id}/{format_type}")
async def export_report(
    scan_id: str,
    format_type: str,
    repository: ScanRepository = Depends(get_repository),
) -> Response:
    """Generate and download reports in CSV, JSON, or HTML format."""
    result: Optional[ScanResult] = await repository.get_scan_result(scan_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    fmt = format_type.lower().strip()
    safe_domain = result.summary.domain.replace(".", "_")

    if fmt == "csv":
        generator = CSVReportGenerator()
        content = generator.generate(result)
        filename = f"subreconx_{safe_domain}_{scan_id}.csv"
        return Response(
            content=content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    elif fmt == "json":
        generator = JSONReportGenerator()
        content = generator.generate(result)
        filename = f"subreconx_{safe_domain}_{scan_id}.json"
        return Response(
            content=content,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    elif fmt == "html":
        generator = HTMLReportGenerator()
        content = generator.generate(result)
        filename = f"subreconx_{safe_domain}_{scan_id}.html"
        return Response(
            content=content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported report format: {format_type!r}. Supported formats: csv, json, html",
        )
