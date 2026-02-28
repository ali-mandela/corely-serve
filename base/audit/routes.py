"""
Audit Routes — admin-only endpoints to view the audit trail.

Endpoints:
    GET  /                     List audit logs (filter by module, action, user, date)
    GET  /{id}                 Get single log entry with full before/after data
    GET  /resource/{id}        Get complete change history for a specific resource
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from datetime import datetime

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .service import AuditService

audit_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract tenant org_slug from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


@audit_router.get("/")
@require_permission("reports:read")
async def list_audit_logs(
    request: Request,
    module: Optional[str] = Query(None, description="users, items, pos, invoices, etc."),
    action: Optional[str] = Query(None, description="create, update, delete, login, etc."),
    user_id: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List audit logs — admin-only view of all actions across the system.

    Common queries:
        - Who edited items today: ?module=items&action=update&from_date=...
        - All actions by a specific user: ?user_id=xxx
        - All login attempts: ?action=login
        - All deletes this week: ?action=delete&from_date=...

    Permission: reports:read (admin/manager only)
    Collection: {slug}_audit_logs
    """
    slug = _get_org_slug(request)
    svc = AuditService(db, slug)
    logs, total = await svc.list_logs(
        module=module, action=action, user_id=user_id,
        resource_id=resource_id,
        from_date=from_date, to_date=to_date,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"logs": logs, "total": total, "limit": limit, "offset": offset}
    )


@audit_router.get("/resource/{resource_id}")
@require_permission("reports:read")
async def resource_history(
    request: Request,
    resource_id: str,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get the complete change history for a specific resource (item, user, customer, etc.).
    Shows every create/update/delete with before/after diffs.

    Permission: reports:read
    Collection: {slug}_audit_logs
    """
    slug = _get_org_slug(request)
    svc = AuditService(db, slug)
    history = await svc.get_resource_history(resource_id, limit)
    return success_response(data={"resource_id": resource_id, "history": history})


@audit_router.get("/{log_id}")
@require_permission("reports:read")
async def get_audit_log(
    request: Request,
    log_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single audit log entry with full before/after data.
    Use this to see exactly what changed in a specific action.

    Permission: reports:read
    Collection: {slug}_audit_logs
    """
    slug = _get_org_slug(request)
    svc = AuditService(db, slug)
    return success_response(data=await svc.get_log(log_id))
