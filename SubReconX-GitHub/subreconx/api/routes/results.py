"""Results querying and pagination API routes."""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from subreconx.api.dependencies import get_repository
from subreconx.db.repositories import ScanRepository
from subreconx.models import ScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Results"])


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    search: Optional[str] = Query(None, description="Search hostname substring"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=500, description="Items per page"),
    sort_by: str = Query("hostname", description="Sort field (hostname, source)"),
    sort_desc: bool = Query(False, description="Sort descending"),
    repository: ScanRepository = Depends(get_repository),
) -> dict[str, Any]:
    """Retrieve full paginated and filtered results for a completed scan."""
    result: Optional[ScanResult] = await repository.get_scan_result(scan_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Build index of DNS and HTTP entries by hostname
    dns_map = {d.hostname: d for d in result.dns_results}
    http_map: dict[str, dict[str, Any]] = {}
    for h in result.http_results:
        if h.hostname not in http_map:
            http_map[h.hostname] = {}
        http_map[h.hostname][h.scheme] = h

    # Consolidate table rows
    rows: list[dict[str, Any]] = []
    for sub in result.subdomains:
        host = sub.hostname
        dns_res = dns_map.get(host)
        host_http = http_map.get(host, {})

        dns_record_list = [
            {"type": r.record_type, "value": r.value, "ttl": r.ttl}
            for r in (dns_res.records if dns_res else [])
        ]

        h_entry = host_http.get("http")
        hs_entry = host_http.get("https")

        row = {
            "hostname": host,
            "source": sub.source,
            "discovered_at": sub.discovered_at.isoformat(),
            "dns_resolved": dns_res.is_resolved if dns_res else False,
            "dns_records": dns_record_list,
            "dns_error": dns_res.error if dns_res else None,
            "http": {
                "status_code": h_entry.status_code if h_entry else None,
                "response_time_ms": h_entry.response_time_ms if h_entry else None,
                "page_title": h_entry.page_title if h_entry else None,
                "error": h_entry.error if h_entry else None,
            }
            if h_entry
            else None,
            "https": {
                "status_code": hs_entry.status_code if hs_entry else None,
                "response_time_ms": hs_entry.response_time_ms if hs_entry else None,
                "page_title": hs_entry.page_title if hs_entry else None,
                "error": hs_entry.error if hs_entry else None,
            }
            if hs_entry
            else None,
        }
        rows.append(row)

    # Filter search
    if search:
        s = search.lower().strip()
        rows = [r for r in rows if s in r["hostname"].lower()]

    # Sort
    if sort_by in ("hostname", "source"):
        rows.sort(key=lambda x: str(x.get(sort_by, "")), reverse=sort_desc)

    total_count = len(rows)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_rows = rows[start_idx:end_idx]

    return {
        "scan_id": scan_id,
        "summary": result.summary.model_dump(),
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": (total_count + per_page - 1) // per_page if per_page else 1,
        "results": paginated_rows,
    }
