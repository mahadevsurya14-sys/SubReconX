"""Scan management and lifecycle API routes."""

import asyncio
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from subreconx.api.dependencies import (
    get_comparator,
    get_orchestrator,
    get_repository,
)
from subreconx.core.comparator import ScanComparator
from subreconx.core.domain_validator import validate_domain
from subreconx.core.orchestrator import ScanOrchestrator
from subreconx.db.repositories import ScanRepository
from subreconx.exceptions import InvalidDomainError
from subreconx.models import (
    ScanComparison,
    ScanConfig,
    ScanRequest,
    ScanStatus,
    ScanStatusResponse,
    ScanSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])


class CompareRequest(BaseModel):
    scan_id_old: str
    scan_id_new: str


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    request: ScanRequest,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    """Validate target domain and launch a new background scan."""
    try:
        clean_domain = validate_domain(request.domain)
    except InvalidDomainError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    config = ScanConfig(
        domain=clean_domain,
        enable_dns=request.enable_dns,
        enable_http=request.enable_http,
        use_subfinder=request.use_subfinder,
        use_amass=request.use_amass,
    )

    summary_stub = ScanSummary(domain=clean_domain)
    scan_id = summary_stub.scan_id

    # Launch non-blocking background task
    task = asyncio.create_task(
        orchestrator.run_scan(config=config, scan_id=scan_id),
        name=f"scan-{scan_id}",
    )
    orchestrator._scan_tasks[scan_id] = task

    return {
        "scan_id": scan_id,
        "domain": clean_domain,
        "status": ScanStatus.RUNNING.value,
        "message": "Scan initiated in background",
    }


@router.get("")
async def list_scans(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    limit: int = Query(50, ge=1, le=200),
    repository: ScanRepository = Depends(get_repository),
) -> list[dict[str, Any]]:
    """List recent scan executions."""
    rows = await repository.list_scans(domain=domain, limit=limit)
    results: list[dict[str, Any]] = []

    for r in rows:
        item = {
            "scan_id": r["id"],
            "domain": r["domain"],
            "status": r["status"],
            "started_at": r["started_at"],
            "completed_at": r["completed_at"],
            "duration_seconds": r["duration_seconds"],
        }
        if r.get("summary_json"):
            try:
                summary_dict = json.loads(r["summary_json"])
                item["total_subdomains"] = summary_dict.get("total_subdomains", 0)
                item["dns_resolved"] = summary_dict.get("dns_resolved", 0)
                item["http_live"] = summary_dict.get("http_live", 0)
            except Exception:
                pass
        results.append(item)

    return results


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
    repository: ScanRepository = Depends(get_repository),
) -> ScanStatusResponse:
    """Retrieve current scan progress and status."""
    scan_row = await repository.get_scan(scan_id)
    if not scan_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID {scan_id!r} not found",
        )

    current_status = orchestrator.get_scan_status(scan_id) or ScanStatus(scan_row["status"])
    summary: Optional[ScanSummary] = None

    if scan_row.get("summary_json"):
        try:
            summary = ScanSummary(**json.loads(scan_row["summary_json"]))
        except Exception:
            pass

    return ScanStatusResponse(
        scan_id=scan_id,
        domain=scan_row["domain"],
        status=current_status,
        progress="In Progress" if current_status == ScanStatus.RUNNING else "Finished",
        summary=summary,
    )


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> dict[str, Any]:
    """Request cancellation of an active scan."""
    cancelled = await orchestrator.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan {scan_id} is not currently running or cannot be cancelled",
        )
    return {"scan_id": scan_id, "status": "cancelled", "message": "Scan cancelled"}


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: str,
    repository: ScanRepository = Depends(get_repository),
) -> dict[str, Any]:
    """Delete a scan record and its associated discovery artifacts."""
    deleted = await repository.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )
    return {"scan_id": scan_id, "message": "Scan deleted successfully"}


@router.post("/compare", response_model=ScanComparison)
async def compare_scans(
    payload: CompareRequest,
    repository: ScanRepository = Depends(get_repository),
    comparator: ScanComparator = Depends(get_comparator),
) -> ScanComparison:
    """Compare two scan runs for historical change detection."""
    old_res = await repository.get_scan_result(payload.scan_id_old)
    if not old_res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {payload.scan_id_old} not found",
        )

    new_res = await repository.get_scan_result(payload.scan_id_new)
    if not new_res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {payload.scan_id_new} not found",
        )

    return comparator.compare(old_res, new_res)
