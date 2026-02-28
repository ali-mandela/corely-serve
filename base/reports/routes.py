"""
Reports Routes — business intelligence and analytics endpoints.

Endpoints:
    GET  /dashboard             Owner's overview (today/month stats, low stock, dues)
    GET  /sales/summary         Sales over time (daily/weekly/monthly)
    GET  /sales/top-items       Top selling items by quantity
    GET  /sales/by-category     Revenue by product category
    GET  /sales/payment-modes   Revenue breakdown by payment mode
    GET  /inventory/valuation   Total stock value (cost vs retail)
    GET  /inventory/low-stock   Items below min stock level
    GET  /customers/top         Top customers by purchase amount
    GET  /vendors/dues          Outstanding payments to vendors
    GET  /gst/summary           GST tax summary for returns filing
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from datetime import datetime

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .service import ReportsService

reports_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract tenant org_slug from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


# ── Dashboard ────────────────────────────────────────────────────


@reports_router.get("/dashboard")
@require_permission("reports:read")
async def dashboard(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Owner's dashboard — everything at a glance in one API call.

    Returns:
        - today: sales count, revenue, tax collected
        - this_month: same but for the current month
        - low_stock_items: count of items below min stock level
        - total_items, total_customers, total_vendors
        - pending_payments: unpaid purchase count and total due

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    return success_response(data=await svc.get_dashboard())


# ── Sales Reports ────────────────────────────────────────────────


@reports_router.get("/sales/summary")
@require_permission("reports:read")
async def sales_summary(
    request: Request,
    period: str = Query("daily", description="daily, weekly, or monthly"),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Sales summary grouped by period — ideal for charts and trend analysis.

    Each row: period label, total_sales, total_revenue, total_tax, total_discount.
    Default last 30 days. Use period=monthly for yearly overview.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.sales_summary(period, from_date, to_date)
    return success_response(data={"summary": data, "period": period})


@reports_router.get("/sales/top-items")
@require_permission("reports:read")
async def top_selling_items(
    request: Request,
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(30, ge=1, le=365),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Top selling items ranked by quantity sold.
    Returns item name, SKU, total quantity, total revenue, times sold.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.top_selling_items(limit, days)
    return success_response(data={"items": data, "period_days": days})


@reports_router.get("/sales/by-category")
@require_permission("reports:read")
async def sales_by_category(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Sales breakdown by product category.
    Shows which categories (cement, plumbing, electrical, etc.) generate
    the most revenue. Uses $lookup to join with items collection.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.sales_by_category(days)
    return success_response(data={"categories": data, "period_days": days})


@reports_router.get("/sales/payment-modes")
@require_permission("reports:read")
async def payment_mode_breakdown(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Revenue breakdown by payment mode (cash, UPI, card, credit, etc.).
    Helps understand payment preferences and cash flow.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.payment_mode_breakdown(days)
    return success_response(data={"modes": data, "period_days": days})


# ── Inventory Reports ────────────────────────────────────────────


@reports_router.get("/inventory/valuation")
@require_permission("reports:read")
async def stock_valuation(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Total inventory valuation — know how much your stock is worth.

    Returns:
        - total_items: count of active items
        - total_stock_units: sum of all quantities
        - cost_value: total at cost price (what you paid)
        - retail_value: total at selling price (what you'll charge)
        - potential_profit: retail_value - cost_value

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    return success_response(data=await svc.stock_valuation())


@reports_router.get("/inventory/low-stock")
@require_permission("reports:read")
async def low_stock_report(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Items below their minimum stock level — sorted by urgency.

    Each item shows: name, SKU, current stock, min level, deficit.
    Use this for daily reorder planning.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.low_stock_report(limit)
    return success_response(data={"items": data, "count": len(data)})


# ── Customer / Vendor Reports ───────────────────────────────────


@reports_router.get("/customers/top")
@require_permission("reports:read")
async def top_customers(
    request: Request,
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(90, ge=1, le=365),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Top customers ranked by total purchase amount.
    Shows customer name, purchase count, total amount, last purchase date.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.top_customers(limit, days)
    return success_response(data={"customers": data, "period_days": days})


@reports_router.get("/vendors/dues")
@require_permission("reports:read")
async def vendor_dues(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Outstanding payment dues to vendors — who do you owe money to?

    Shows vendor name, GSTIN, total purchases, total paid, outstanding amount.
    Sorted by highest outstanding first.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.vendor_dues()
    return success_response(data={"vendors": data, "count": len(data)})


# ── GST / Tax Report ────────────────────────────────────────────


@reports_router.get("/gst/summary")
@require_permission("reports:read")
async def gst_summary(
    request: Request,
    from_date: Optional[datetime] = Query(None, description="Defaults to 1st of current month"),
    to_date: Optional[datetime] = Query(None, description="Defaults to today"),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    GST tax summary — essential for filing GST returns (GSTR-3B).

    Returns total CGST, SGST, IGST, cess collected from issued invoices
    for the given period. Defaults to current month.

    Permission: reports:read
    """
    slug = _get_org_slug(request)
    svc = ReportsService(db, slug)
    data = await svc.gst_summary(from_date, to_date)
    return success_response(data=data)
