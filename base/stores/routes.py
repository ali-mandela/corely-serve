"""
Stores Routes — manage locations, branches, godowns, and stock transfers.

Endpoints:
    POST   /                            Create store/branch/godown
    GET    /                            List stores (filter by type, status, search)
    GET    /{id}                        Get single store
    PUT    /{id}                        Update store details
    DELETE /{id}                        Soft delete store

    POST   /transfers                   Create a stock transfer between stores
    GET    /transfers                   List transfers (filter by status, store)
    GET    /transfers/{id}              Get single transfer
    PUT    /transfers/{id}/dispatch     Dispatch transfer (deduct stock from source)
    PUT    /transfers/{id}/receive      Receive transfer (add stock at destination)
    PUT    /transfers/{id}/cancel       Cancel pending transfer
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import (
    CreateStoreRequest,
    UpdateStoreRequest,
    CreateStockTransferRequest,
    ReceiveTransferRequest,
)
from .service import StoresService

stores_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract tenant org_slug from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


# ── Store CRUD ───────────────────────────────────────────────────


@stores_router.post("/")
@require_permission("stores:create")
async def create_store(
    request: Request,
    body: CreateStoreRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new store, branch, or godown.

    Store types: shop (retail), branch (another location), godown (warehouse), site (construction).
    Store code must be unique (e.g. MAIN, BR-01, GD-NORTH).
    Setting is_default=true will unset default on all other stores.

    Permission: stores:create
    Collection: {slug}_stores
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    store = await svc.create_store(body.model_dump(), request.state.user.get("sub"))
    return success_response(data=store, message="Store created", code=201)


@stores_router.get("/")
@require_permission("stores:read")
async def list_stores(
    request: Request,
    store_type: Optional[str] = Query(None, description="shop, branch, godown, site"),
    status: Optional[str] = Query(None, description="active, inactive, temporarily_closed"),
    q: Optional[str] = Query(None, description="Search by name, code, or city"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all stores/branches/godowns.

    Permission: stores:read
    Collection: {slug}_stores
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    stores, total = await svc.list_stores(store_type, status, q, limit, offset)
    return success_response(
        data={"stores": stores, "total": total, "limit": limit, "offset": offset}
    )


@stores_router.get("/{store_id}")
@require_permission("stores:read")
async def get_store(
    request: Request,
    store_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single store with all details — address, contact, manager, hours.

    Permission: stores:read
    Collection: {slug}_stores
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    return success_response(data=await svc.get_store(store_id))


@stores_router.put("/{store_id}")
@require_permission("stores:update")
async def update_store(
    request: Request,
    store_id: str,
    body: UpdateStoreRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update store details. Setting is_default=true will make this
    the primary store and unset default on all others.

    Permission: stores:update
    Collection: {slug}_stores
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    store = await svc.update_store(store_id, body.model_dump(exclude_unset=True))
    return success_response(data=store, message="Store updated")


@stores_router.delete("/{store_id}")
@require_permission("stores:delete")
async def delete_store(
    request: Request,
    store_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Soft delete a store. The store record is preserved but marked as deleted.

    Permission: stores:delete
    Collection: {slug}_stores
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    await svc.delete_store(store_id)
    return success_response(message="Store deleted")


# ── Stock Transfers ──────────────────────────────────────────────


@stores_router.post("/transfers")
@require_permission("stores:create")
async def create_transfer(
    request: Request,
    body: CreateStockTransferRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a stock transfer between two stores.

    Transfer lifecycle:
        1. POST /transfers           — status: pending (no stock touched)
        2. PUT  /transfers/{id}/dispatch — status: in_transit (stock deducted from source)
        3. PUT  /transfers/{id}/receive  — status: received (stock added at destination)

    Transfer number: TRF-YYYYMMDD-XXXX

    Permission: stores:create
    Collections: {slug}_stock_transfers, {slug}_stock_movements, {slug}_items
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    transfer = await svc.create_transfer(body.model_dump(), request.state.user.get("sub"))
    return success_response(data=transfer, message="Transfer created", code=201)


@stores_router.get("/transfers")
@require_permission("stores:read")
async def list_transfers(
    request: Request,
    status: Optional[str] = Query(None, description="pending, in_transit, received, cancelled"),
    store_id: Optional[str] = Query(None, description="Show transfers involving this store"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List stock transfers — filter by status or store.

    Permission: stores:read
    Collection: {slug}_stock_transfers
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    transfers, total = await svc.list_transfers(status, store_id, limit, offset)
    return success_response(
        data={"transfers": transfers, "total": total, "limit": limit, "offset": offset}
    )


@stores_router.get("/transfers/{transfer_id}")
@require_permission("stores:read")
async def get_transfer(
    request: Request,
    transfer_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single transfer with all items, status, and timestamps.

    Permission: stores:read
    Collection: {slug}_stock_transfers
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    return success_response(data=await svc.get_transfer(transfer_id))


@stores_router.put("/transfers/{transfer_id}/dispatch")
@require_permission("stores:update")
async def dispatch_transfer(
    request: Request,
    transfer_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Dispatch a pending transfer — goods leave the source store.

    What happens:
        - Status changes from 'pending' to 'in_transit'
        - transfer_out movements are created for each item
        - Stock is deducted from source store's inventory

    Permission: stores:update
    Collections: {slug}_stock_transfers, {slug}_stock_movements, {slug}_items
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    result = await svc.dispatch_transfer(transfer_id, request.state.user.get("sub"))
    return success_response(data=result, message="Transfer dispatched, stock deducted from source")


@stores_router.put("/transfers/{transfer_id}/receive")
@require_permission("stores:update")
async def receive_transfer(
    request: Request,
    transfer_id: str,
    body: ReceiveTransferRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Receive a dispatched transfer — goods arrive at destination store.

    Supports partial receipt: send received_items with actual quantities
    if not all items/quantities arrived.

    What happens:
        - Status changes from 'in_transit' to 'received'
        - transfer_in movements are created for received items
        - Stock is added to destination store's inventory

    Permission: stores:update
    Collections: {slug}_stock_transfers, {slug}_stock_movements, {slug}_items
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    result = await svc.receive_transfer(transfer_id, body.model_dump(), request.state.user.get("sub"))
    return success_response(data=result, message="Transfer received, stock added at destination")


@stores_router.put("/transfers/{transfer_id}/cancel")
@require_permission("stores:update")
async def cancel_transfer(
    request: Request,
    transfer_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Cancel a pending transfer (before dispatch only).
    Cannot cancel a transfer that's already in_transit or received.

    Permission: stores:update
    Collection: {slug}_stock_transfers
    """
    slug = _get_org_slug(request)
    svc = StoresService(db, slug)
    result = await svc.cancel_transfer(transfer_id)
    return success_response(data=result, message="Transfer cancelled")
