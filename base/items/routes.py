from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import CreateItemRequest, UpdateItemRequest
from .service import ItemService

items_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


@items_router.post("/")
@require_permission("products:create")
async def create_item(
    request: Request,
    body: CreateItemRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Create a new item/product in this organization's catalog."""
    slug = _get_org_slug(request)
    current_user = request.state.user
    svc = ItemService(db, slug)
    item = await svc.create_item(
        data=body.model_dump(),
        created_by=current_user.get("sub"),
    )
    return success_response(data=item, message="Item created", code=201)


@items_router.get("/")
@require_permission("products:read")
async def list_items(
    request: Request,
    q: Optional[str] = Query(None, description="Search by name, SKU, barcode, brand"),
    category: Optional[str] = Query(None, description="Filter by category"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """List items with optional search by name/SKU/barcode/brand, and category/status filters."""
    slug = _get_org_slug(request)
    svc = ItemService(db, slug)
    items, total = await svc.list_items(
        query=q, category=category, status_filter=status,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"items": items, "total": total, "limit": limit, "offset": offset}
    )


@items_router.get("/{item_id}")
@require_permission("products:read")
async def get_item(
    request: Request,
    item_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get a single item by ID."""
    slug = _get_org_slug(request)
    svc = ItemService(db, slug)
    item = await svc.get_item(item_id)
    return success_response(data=item)


@items_router.put("/{item_id}")
@require_permission("products:update")
async def update_item(
    request: Request,
    item_id: str,
    body: UpdateItemRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Update item fields by ID."""
    slug = _get_org_slug(request)
    svc = ItemService(db, slug)
    item = await svc.update_item(item_id, body.model_dump(exclude_unset=True))
    return success_response(data=item, message="Item updated")


@items_router.delete("/{item_id}")
@require_permission("products:delete")
async def delete_item(
    request: Request,
    item_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Soft-delete an item by ID."""
    slug = _get_org_slug(request)
    svc = ItemService(db, slug)
    result = await svc.delete_item(item_id)
    return success_response(data=result, message="Item deleted")
