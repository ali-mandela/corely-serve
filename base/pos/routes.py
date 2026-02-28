"""
POS Routes — API endpoints for point-of-sale operations.

Endpoints:
    POST   /sales              Create a new sale / bill
    GET    /sales              List sales (filter by status, customer, date, search)
    GET    /sales/{id}         Get single sale with line items and payment
    PUT    /sales/{id}/hold    Park a bill for later
    PUT    /sales/{id}/complete Complete a held/draft sale with payment
    PUT    /sales/{id}/cancel  Cancel a draft/held sale
    POST   /sales/{id}/return  Return items from a completed sale
    GET    /daily-summary      Today's sales summary (total sales, amount, tax)
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from datetime import datetime

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import (
    CreateSaleRequest,
    HoldSaleRequest,
    CompleteSaleRequest,
    SaleReturnRequest,
)
from .service import POSService

pos_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract tenant org_slug from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


# ── Create Sale ──────────────────────────────────────────────────


@pos_router.post("/sales")
@require_permission("pos:create")
async def create_sale(
    request: Request,
    body: CreateSaleRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new sale / bill at the counter.

    If status='completed' (default), stock is immediately deducted and an
    invoice number is generated (INV-YYYYMMDD-XXXX).

    If status='draft' or 'on_hold', stock is NOT touched until the sale
    is explicitly completed via PUT /sales/{id}/complete.

    Walk-in customers: just leave customer_id blank and optionally set
    customer_name for the receipt.

    Permission: pos:create
    Collections: {slug}_sales, {slug}_stock_movements, {slug}_items
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    sale = await svc.create_sale(
        data=body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=sale, message="Sale created", code=201)


# ── List Sales ───────────────────────────────────────────────────


@pos_router.get("/sales")
@require_permission("pos:read")
async def list_sales(
    request: Request,
    status: Optional[str] = Query(None, description="completed, draft, on_hold, cancelled, returned"),
    customer_id: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Search by invoice number, customer name/phone"),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all sales with optional filters.

    Common use cases:
        - Today's bills: GET /sales?from_date=2026-03-01T00:00:00
        - Held bills: GET /sales?status=on_hold
        - Customer history: GET /sales?customer_id=xxx
        - Search by invoice: GET /sales?q=INV-20260301

    Permission: pos:read
    Collection: {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    sales, total = await svc.list_sales(
        status_filter=status, customer_id=customer_id,
        from_date=from_date, to_date=to_date,
        query=q, limit=limit, offset=offset,
    )
    return success_response(
        data={"sales": sales, "total": total, "limit": limit, "offset": offset}
    )


# ── Get Single Sale ──────────────────────────────────────────────


@pos_router.get("/sales/{sale_id}")
@require_permission("pos:read")
async def get_sale(
    request: Request,
    sale_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single sale by ID with all line items, GST breakdown, and payment details.
    Use this to view or reprint a bill/invoice.

    Permission: pos:read
    Collection: {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    return success_response(data=await svc.get_sale(sale_id))


# ── Hold Sale ────────────────────────────────────────────────────


@pos_router.put("/sales/{sale_id}/hold")
@require_permission("pos:update")
async def hold_sale(
    request: Request,
    sale_id: str,
    body: HoldSaleRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Park a draft sale for later — customer will come back.
    Stock is NOT deducted. The bill stays in 'on_hold' status until
    completed or cancelled.

    Permission: pos:update
    Collection: {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    result = await svc.hold_sale(sale_id, body.reason)
    return success_response(data=result, message="Sale put on hold")


# ── Complete Sale ────────────────────────────────────────────────


@pos_router.put("/sales/{sale_id}/complete")
@require_permission("pos:update")
async def complete_sale(
    request: Request,
    sale_id: str,
    body: CompleteSaleRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Complete a held or draft sale — record payment and deduct stock.

    This is called when the customer returns to pay for a held bill,
    or when a draft bill is finalized. An invoice number is generated
    and stock is deducted for all line items.

    Permission: pos:update
    Collections: {slug}_sales, {slug}_stock_movements, {slug}_items
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    result = await svc.complete_sale(
        sale_id, body.model_dump(),
        completed_by=request.state.user.get("sub"),
    )
    return success_response(data=result, message="Sale completed, stock deducted")


# ── Cancel Sale ──────────────────────────────────────────────────


@pos_router.put("/sales/{sale_id}/cancel")
@require_permission("pos:update")
async def cancel_sale(
    request: Request,
    sale_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Cancel a draft or held sale. Only works on non-completed sales.
    For completed sales, use the return endpoint instead.

    Permission: pos:update
    Collection: {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    result = await svc.cancel_sale(sale_id)
    return success_response(data=result, message="Sale cancelled")


# ── Sale Return ──────────────────────────────────────────────────


@pos_router.post("/sales/{sale_id}/return")
@require_permission("pos:create")
async def process_return(
    request: Request,
    sale_id: str,
    body: SaleReturnRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Return items from a completed sale — creates a credit note.

    What happens:
        1. Validates the original sale exists and is completed
        2. Creates a return document in {slug}_sale_returns
        3. Adds stock back via return_in movements
        4. Updates original sale status to 'returned'

    The refund can be in any payment mode (cash is default).

    Permission: pos:create
    Collections: {slug}_sale_returns, {slug}_stock_movements, {slug}_items, {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    result = await svc.process_return(
        sale_id, body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=result, message="Return processed, stock restored", code=201)


# ── Daily Summary ────────────────────────────────────────────────


@pos_router.get("/daily-summary")
@require_permission("pos:read")
async def daily_summary(
    request: Request,
    date: Optional[datetime] = Query(None, description="Defaults to today (UTC)"),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get sales summary for a specific day (defaults to today).

    Returns:
        - total_sales: number of completed sales
        - total_amount: sum of grand_total
        - total_tax: sum of GST collected
        - total_discount: sum of discounts given
        - total_items_sold: count of line items across all sales

    Use this for the daily cash register close report.

    Permission: pos:read
    Collection: {slug}_sales
    """
    slug = _get_org_slug(request)
    svc = POSService(db, slug)
    summary = await svc.get_daily_summary(date)
    return success_response(data=summary)
