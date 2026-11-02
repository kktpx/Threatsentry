from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from supabase import Client

from backend.api.deps.auth import get_current_user_id
from backend.api.routers.websites import _owned_website, get_database

router = APIRouter(tags=["findings"])


def _owned_scan(database: Client, scan_id: str, user_id: str) -> dict[str, Any]:
    response = (
        database.table("scan_jobs")
        .select("*")
        .eq("id", scan_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not response.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return response.data[0]


@router.get("/api/scans/{scan_id}/findings")
def list_scan_findings(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Client = Depends(get_database),
) -> list[dict[str, Any]]:
    _owned_scan(database, scan_id, user_id)
    response = (
        database.table("findings")
        .select("*")
        .eq("scan_id", scan_id)
        .eq("user_id", user_id)
        .order("created_at", desc=False)
        .execute()
    )
    return response.data


@router.get("/api/websites/{website_id}/findings")
def list_website_findings(
    website_id: str,
    all_scans: bool = False,
    user_id: str = Depends(get_current_user_id),
    database: Client = Depends(get_database),
) -> list[dict[str, Any]]:
    """Findings of the latest completed scan; pass all_scans=true for every scan's findings."""
    _owned_website(database, website_id, user_id)
    query = (
        database.table("findings")
        .select("*")
        .eq("website_id", website_id)
        .eq("user_id", user_id)
    )
    if not all_scans:
        latest = (
            database.table("scan_jobs")
            .select("id")
            .eq("website_id", website_id)
            .eq("user_id", user_id)
            .eq("status", "COMPLETED")
            .order("created_at", desc=True)
            .execute()
        )
        if latest.data:
            query = query.eq("scan_id", latest.data[0]["id"])
    return query.order("created_at", desc=True).execute().data


@router.get("/api/findings/{finding_id}")
def get_finding(
    finding_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Client = Depends(get_database),
) -> dict[str, Any]:
    response = (
        database.table("findings")
        .select("*")
        .eq("id", finding_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not response.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return response.data[0]
