from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import CreateVendorRequest, UpdateVendorRequest
from .service import VendorService

vendors_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


@vendors_router.post("/")
@require_permission("vendors:create")
async def create_vendor(
    request: Request,
    body: CreateVendorRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Create a new vendor/supplier for this organization."""
    slug = _get_org_slug(request)
    svc = VendorService(db, slug)
    vendor = await svc.create_vendor(
        data=body.model_dump(), created_by=request.state.user.get("sub"),
    )
    return success_response(data=vendor, message="Vendor created", code=201)


@vendors_router.get("/")
@require_permission("vendors:read")
async def list_vendors(
    request: Request,
    q: Optional[str] = Query(None),
    vendor_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """List vendors with optional search, type, and status filters."""
    slug = _get_org_slug(request)
    svc = VendorService(db, slug)
    vendors, total = await svc.list_vendors(
        query=q, vendor_type=vendor_type, status_filter=status,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"vendors": vendors, "total": total, "limit": limit, "offset": offset}
    )


@vendors_router.get("/{vendor_id}")
@require_permission("vendors:read")
async def get_vendor(
    request: Request, vendor_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get a single vendor by ID."""
    slug = _get_org_slug(request)
    svc = VendorService(db, slug)
    return success_response(data=await svc.get_vendor(vendor_id))


@vendors_router.put("/{vendor_id}")
@require_permission("vendors:update")
async def update_vendor(
    request: Request, vendor_id: str, body: UpdateVendorRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Update vendor fields by ID."""
    slug = _get_org_slug(request)
    svc = VendorService(db, slug)
    vendor = await svc.update_vendor(vendor_id, body.model_dump(exclude_unset=True))
    return success_response(data=vendor, message="Vendor updated")


@vendors_router.delete("/{vendor_id}")
@require_permission("vendors:delete")
async def delete_vendor(
    request: Request, vendor_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Soft-delete a vendor by ID."""
    slug = _get_org_slug(request)
    svc = VendorService(db, slug)
    result = await svc.delete_vendor(vendor_id)
    return success_response(data=result, message="Vendor deleted")
