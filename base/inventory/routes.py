"""
Inventory Routes — API endpoints for managing stock movements, purchase entries,
stock adjustments, and inventory reports.

This module provides the HTTP interface for all inventory operations within a
tenant-scoped (multi-tenant) system. Every endpoint requires JWT authentication
and appropriate RBAC permissions under the 'inventory' module.

Collections used (all prefixed with org_slug):
    - {org_slug}_stock_movements  : Records of every stock change
    - {org_slug}_purchase_entries : Purchase / GRN records from vendors
    - {org_slug}_items            : Item catalog (stock field updated on movements)

Key concepts:
    - Stock IN  : Purchases, customer returns, transfers in, opening stock
    - Stock OUT : Sales (POS), returns to vendor, transfers out
    - Adjustments : Manual corrections for damage, theft, physical count, wastage
    - Ledger : Complete movement history for a single item (like a bank statement)
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from datetime import datetime

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import (
    StockMovementRequest,
    PurchaseEntryRequest,
    StockAdjustmentRequest,
)
from .service import InventoryService

inventory_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """
    Extract the organization slug from the request state.

    The org_slug is injected by the AuthPermissionMiddleware after decoding
    the JWT token. It identifies which tenant's data to operate on.
    All inventory collections are prefixed with this slug, e.g. 'lhs_stock_movements'.

    Raises:
        ValueError: If org_slug is missing (should never happen for authenticated routes).
    """
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


# ── Stock Movements ──────────────────────────────────────────────


@inventory_router.post("/movements")
@require_permission("inventory:create")
async def record_movement(
    request: Request,
    body: StockMovementRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Record a stock movement — the fundamental building block of inventory tracking.

    Every change to stock quantity is recorded as a movement. This endpoint handles
    all movement types:

        - stock_in       : Goods received (purchase, opening stock)
        - stock_out      : Goods issued (manual sale, issued to site)
        - transfer_in    : Received from another warehouse/location
        - transfer_out   : Sent to another warehouse/location
        - return_in      : Customer returned goods back to store
        - return_out     : Goods returned to vendor/supplier
        - opening_stock  : Initial stock entry when setting up inventory
        - adjustment     : Manual correction (use POST /adjustments instead for better tracking)

    Side effects:
        - Automatically updates the item's current_stock in the items collection.
        - stock_in/return_in/transfer_in/opening_stock INCREASE stock.
        - stock_out/return_out/transfer_out DECREASE stock.

    When POS is built, sale transactions will internally call this endpoint
    with movement_type='stock_out' so the cashier doesn't need to think about inventory.

    Permission: inventory:create
    Collection: {org_slug}_stock_movements
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    result = await svc.record_movement(
        data=body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=result, message="Stock movement recorded", code=201)


@inventory_router.get("/movements")
@require_permission("inventory:read")
async def list_movements(
    request: Request,
    item_id: Optional[str] = Query(None),
    movement_type: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all stock movements with optional filters.

    Use this to audit stock changes, investigate discrepancies, or generate
    movement reports. Results are sorted by most recent first.

    Filters:
        - item_id       : Show movements for a specific item only
        - movement_type : Filter by type (stock_in, stock_out, adjustment, etc.)
        - from_date     : Movements on or after this UTC datetime
        - to_date       : Movements on or before this UTC datetime

    Example use cases:
        - "Show me all stock_out movements this week" (to track what was sold/issued)
        - "Show me all movements for item X" (to investigate stock discrepancy)
        - "Show me all return_in movements" (to track customer returns)

    Permission: inventory:read
    Collection: {org_slug}_stock_movements
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    movements, total = await svc.list_movements(
        item_id=item_id, movement_type=movement_type,
        from_date=from_date, to_date=to_date,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"movements": movements, "total": total, "limit": limit, "offset": offset}
    )


# ── Purchase Entries ─────────────────────────────────────────────


@inventory_router.post("/purchases")
@require_permission("inventory:create")
async def create_purchase(
    request: Request,
    body: PurchaseEntryRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Record a purchase entry (Goods Received Note / GRN) from a vendor.

    This is the primary way to add stock to inventory. When goods arrive from
    a supplier, record the purchase here with all line items, pricing, and
    GST details.

    What happens internally:
        1. The purchase entry document is saved to {org_slug}_purchase_entries
        2. For EACH line item, a 'stock_in' movement is auto-created in {org_slug}_stock_movements
        3. Each item's current_stock is incremented by the received quantity

    India-specific fields supported:
        - Supplier GSTIN (15-digit, validated)
        - GST type: CGST+SGST (intra-state) or IGST (inter-state)
        - HSN codes per line item
        - E-way bill number (mandatory for goods > INR 50,000)
        - Invoice number, challan number, PO number
        - Transport details (transporter name, vehicle number)

    Payment tracking:
        - Payment status: unpaid / partial / paid
        - Payment mode: cash / UPI / NEFT-RTGS / cheque / credit / card
        - Amount paid vs grand total for outstanding balance tracking

    Permission: inventory:create
    Collections: {org_slug}_purchase_entries, {org_slug}_stock_movements, {org_slug}_items
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    result = await svc.create_purchase(
        data=body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=result, message="Purchase recorded, stock updated", code=201)


@inventory_router.get("/purchases")
@require_permission("inventory:read")
async def list_purchases(
    request: Request,
    supplier: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    payment_status: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all purchase entries with optional filters.

    Use this to review purchase history, track pending payments, or audit
    vendor transactions. Results are sorted by most recent first.

    Filters:
        - supplier       : Search by supplier/vendor name (partial match)
        - status         : Purchase status (draft, ordered, partially_received, received, cancelled)
        - payment_status : Payment status (unpaid, partial, paid)
        - from_date      : Purchases on or after this UTC datetime
        - to_date        : Purchases on or before this UTC datetime

    Example use cases:
        - "Show me all unpaid purchases" (to track outstanding vendor payments)
        - "Show me all purchases from vendor X this month" (for vendor reconciliation)
        - "Show me all partially received orders" (to follow up on pending deliveries)

    Permission: inventory:read
    Collection: {org_slug}_purchase_entries
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    purchases, total = await svc.list_purchases(
        supplier_name=supplier, status_filter=status,
        payment_status=payment_status,
        from_date=from_date, to_date=to_date,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"purchases": purchases, "total": total, "limit": limit, "offset": offset}
    )


@inventory_router.get("/purchases/{purchase_id}")
@require_permission("inventory:read")
async def get_purchase(
    request: Request,
    purchase_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single purchase entry by its ID.

    Returns the full purchase document including:
        - Supplier details (name, GSTIN, address, state)
        - All line items with quantities, pricing, GST per item
        - GST summary (CGST, SGST, IGST totals)
        - Payment status and amount paid
        - Transport and logistics details
        - Invoice, challan, and PO numbers

    Use this to view a specific purchase bill/invoice or for printing a GRN.

    Permission: inventory:read
    Collection: {org_slug}_purchase_entries
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    result = await svc.get_purchase(purchase_id)
    return success_response(data=result)


# ── Stock Adjustments ────────────────────────────────────────────


@inventory_router.post("/adjustments")
@require_permission("inventory:create")
async def adjust_stock(
    request: Request,
    body: StockAdjustmentRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Manually adjust stock for an item with a mandatory reason.

    Use this when stock needs to be corrected outside of normal purchase/sale flow.
    Every adjustment is tracked as a stock movement for full audit trail.

    Common scenarios:
        - Physical stock count doesn't match system count -> reason: 'physical_count'
        - Items damaged in storage or transit            -> reason: 'damage'
        - Items expired (paint, adhesives, etc.)         -> reason: 'expired'
        - Theft or unexplained loss                      -> reason: 'theft_loss'
        - Items given as free samples                    -> reason: 'sample'
        - Material wastage during handling               -> reason: 'wastage'
        - Data entry correction                          -> reason: 'correction'

    What happens internally:
        - adjustment_type='increase' creates a stock_in movement and adds to stock
        - adjustment_type='decrease' creates a stock_out movement and subtracts from stock
        - The reason is stored on the movement for audit purposes

    Permission: inventory:create
    Collections: {org_slug}_stock_movements, {org_slug}_items
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    result = await svc.adjust_stock(
        data=body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=result, message="Stock adjusted", code=201)


# ── Stock Reports ────────────────────────────────────────────────


@inventory_router.get("/stock-summary")
@require_permission("inventory:read")
async def stock_summary(
    request: Request,
    category: Optional[str] = Query(None),
    low_stock: bool = Query(False, description="Only show items below min_stock_level"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get current stock levels for all items — the inventory dashboard view.

    Returns a summary of each item's stock position including:
        - Item name, SKU, category, unit
        - Current stock quantity
        - Min/max stock levels and reorder level
        - Selling price and cost price
        - Item status (active, inactive, discontinued)

    Key feature — Low stock alert:
        Set low_stock=true to only see items where current_stock is at or below
        the item's min_stock_level. Use this for daily reorder planning.

    Filters:
        - category   : Filter by item category (cement_concrete, plumbing, etc.)
        - low_stock  : If true, only returns items below their min_stock_level

    Example use cases:
        - Morning stock check: GET /stock-summary?low_stock=true
        - Category review: GET /stock-summary?category=cement_concrete
        - Full inventory snapshot: GET /stock-summary?limit=200

    Permission: inventory:read
    Collection: {org_slug}_items (reads stock fields from items catalog)
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    items, total = await svc.get_stock_summary(
        low_stock_only=low_stock, category=category,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"items": items, "total": total, "limit": limit, "offset": offset}
    )


@inventory_router.get("/ledger/{item_id}")
@require_permission("inventory:read")
async def item_ledger(
    request: Request,
    item_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get the full stock movement ledger for a single item.

    Think of this as a bank statement, but for stock — every deposit (stock_in)
    and withdrawal (stock_out) is listed in chronological order.

    Each movement record shows:
        - Movement type (stock_in, stock_out, adjustment, transfer, return)
        - Quantity and unit
        - Reference (which purchase, sale, or adjustment caused this)
        - Unit cost at the time of movement
        - Location (for transfers between warehouses)
        - Reason (for adjustments — damage, theft, count correction, etc.)
        - Who created it and when

    Use this to:
        - Investigate why stock doesn't match physical count
        - Track an item's complete history from purchase to sale
        - Audit who made stock changes and when
        - Generate item-level inventory reports

    Permission: inventory:read
    Collection: {org_slug}_stock_movements (filtered by item_id)
    """
    slug = _get_org_slug(request)
    svc = InventoryService(db, slug)
    movements, total = await svc.get_item_ledger(
        item_id=item_id, limit=limit, offset=offset,
    )
    return success_response(
        data={"item_id": item_id, "movements": movements, "total": total}
    )
