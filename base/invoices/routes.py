"""
Invoice Routes — API endpoints for managing GST-compliant invoices.

Endpoints:
    POST   /                   Create a new invoice manually
    POST   /from-sale          Auto-generate invoice from a POS sale
    GET    /                   List invoices (filter by type, status, search, date)
    GET    /{id}               Get single invoice with all details
    PUT    /{id}               Update invoice (draft/issued only)
    PUT    /{id}/cancel        Cancel an invoice
"""

from fastapi import APIRouter, Depends, Request, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional
from datetime import datetime

from base.config import get_database
from base.utils import success_response
from base.rbac.decorators import require_permission
from .schemas import CreateInvoiceRequest, UpdateInvoiceRequest, GenerateFromSaleRequest
from .service import InvoiceService

invoices_router = APIRouter()


def _get_org_slug(request: Request) -> str:
    """Extract tenant org_slug from JWT-decoded request state."""
    slug = getattr(request.state, "org_slug", None)
    if not slug:
        raise ValueError("org_slug not found on request")
    return slug


# ── Create Invoice ───────────────────────────────────────────────


@invoices_router.post("/")
@require_permission("invoices:create")
async def create_invoice(
    request: Request,
    body: CreateInvoiceRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new invoice manually.

    Supports all invoice types: tax_invoice, credit_note, debit_note,
    quotation, proforma, delivery_challan.

    Auto-generates:
        - Invoice number per type and financial year (e.g. TI-2526-0001)
        - HSN-wise tax summary (if not provided)
        - Amount in words (e.g. 'Rupees Five Thousand Only')

    Permission: invoices:create
    Collection: {slug}_invoices
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    invoice = await svc.create_invoice(
        data=body.model_dump(),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=invoice, message="Invoice created", code=201)


# ── Generate from POS Sale ───────────────────────────────────────


@invoices_router.post("/from-sale")
@require_permission("invoices:create")
async def generate_from_sale(
    request: Request,
    body: GenerateFromSaleRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Auto-generate a tax invoice from a completed POS sale.

    What happens:
        1. Reads the sale and all its line items
        2. Maps to invoice format with proper GST breakdown
        3. Auto-fills buyer info from customer record (if linked)
        4. Calculates HSN summary and amount in words
        5. Generates invoice number (TI-XXYY-NNNN)

    Prevents duplicate invoices — returns 409 if one already exists
    for this sale.

    Permission: invoices:create
    Collections: {slug}_invoices, {slug}_sales, {slug}_customers
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    invoice = await svc.generate_from_sale(
        sale_id=body.sale_id,
        extra_data=body.model_dump(exclude={"sale_id"}),
        created_by=request.state.user.get("sub"),
    )
    return success_response(data=invoice, message="Invoice generated from sale", code=201)


# ── List Invoices ────────────────────────────────────────────────


@invoices_router.get("/")
@require_permission("invoices:read")
async def list_invoices(
    request: Request,
    invoice_type: Optional[str] = Query(None, description="tax_invoice, credit_note, quotation, etc."),
    status: Optional[str] = Query(None, description="draft, issued, paid, overdue, cancelled"),
    q: Optional[str] = Query(None, description="Search by invoice number, buyer name/GSTIN"),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List invoices with optional filters.

    Common queries:
        - All tax invoices this month: ?invoice_type=tax_invoice&from_date=2026-03-01
        - All unpaid invoices: ?status=issued
        - Search by buyer GSTIN: ?q=29ABCDE1234F1Z5
        - Credit notes only: ?invoice_type=credit_note

    Permission: invoices:read
    Collection: {slug}_invoices
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    invoices, total = await svc.list_invoices(
        invoice_type=invoice_type, status_filter=status,
        query=q, from_date=from_date, to_date=to_date,
        limit=limit, offset=offset,
    )
    return success_response(
        data={"invoices": invoices, "total": total, "limit": limit, "offset": offset}
    )


# ── Get Single Invoice ──────────────────────────────────────────


@invoices_router.get("/{invoice_id}")
@require_permission("invoices:read")
async def get_invoice(
    request: Request,
    invoice_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Get a single invoice with full details.

    Returns seller/buyer info, all line items with GST breakdown,
    HSN summary, payment terms, bank details, and amount in words.
    Use this data to render a printable invoice.

    Permission: invoices:read
    Collection: {slug}_invoices
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    return success_response(data=await svc.get_invoice(invoice_id))


# ── Update Invoice ───────────────────────────────────────────────


@invoices_router.put("/{invoice_id}")
@require_permission("invoices:update")
async def update_invoice(
    request: Request,
    invoice_id: str,
    body: UpdateInvoiceRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update an invoice — only works on draft or issued invoices.
    Paid or cancelled invoices cannot be modified (issue a credit note instead).

    If grand_total is changed, amount_in_words is auto-recalculated.

    Permission: invoices:update
    Collection: {slug}_invoices
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    invoice = await svc.update_invoice(invoice_id, body.model_dump(exclude_unset=True))
    return success_response(data=invoice, message="Invoice updated")


# ── Cancel Invoice ───────────────────────────────────────────────


@invoices_router.put("/{invoice_id}/cancel")
@require_permission("invoices:update")
async def cancel_invoice(
    request: Request,
    invoice_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Cancel an invoice — only works on draft or issued invoices.
    As per GST rules, you cannot delete an invoice once issued. Instead,
    cancel it and issue a credit note if refund is needed.

    Permission: invoices:update
    Collection: {slug}_invoices
    """
    slug = _get_org_slug(request)
    svc = InvoiceService(db, slug)
    result = await svc.cancel_invoice(invoice_id)
    return success_response(data=result, message="Invoice cancelled")
