"""
Invoice Service — create, list, update, cancel invoices and auto-generate from POS sales.

Collections used (all tenant-scoped):
    - {slug}_invoices     : Invoice / credit note / quotation documents
    - {slug}_sales        : POS sales (read-only, for auto-generation)
    - {slug}_customers    : Customer details (for buyer info)

Invoice number formats (per financial year):
    - Tax Invoice   : TI-2526-0001  (FY 2025-26)
    - Credit Note   : CN-2526-0001
    - Debit Note    : DN-2526-0001
    - Quotation     : QT-2526-0001
    - Proforma      : PI-2526-0001
    - Delivery Challan : DC-2526-0001
"""

from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi import HTTPException, status
from bson import ObjectId

from base.tenant import get_tenant_collection
from base.utils import serialize_mongo_doc


# ── Helpers ──────────────────────────────────────────────────────


def _get_fy_code() -> str:
    """
    Get current Indian financial year code.
    FY runs Apr-Mar. e.g. March 2026 = FY 2025-26 = '2526'
    """
    now = datetime.now(timezone.utc)
    year = now.year
    month = now.month
    if month < 4:  # Jan-Mar belongs to previous FY
        start_year = year - 1
    else:
        start_year = year
    end_year = start_year + 1
    return f"{str(start_year)[2:]}{str(end_year)[2:]}"


PREFIX_MAP = {
    "tax_invoice": "TI",
    "credit_note": "CN",
    "debit_note": "DN",
    "quotation": "QT",
    "proforma": "PI",
    "delivery_challan": "DC",
}


def _build_hsn_summary(items: list) -> list:
    """
    Auto-calculate HSN-wise tax summary from line items.
    Groups items by HSN code and aggregates quantities and tax amounts.
    """
    hsn_map: dict = defaultdict(
        lambda: {
            "hsn_code": "",
            "total_quantity": 0,
            "taxable_value": 0,
            "cgst": 0,
            "sgst": 0,
            "igst": 0,
            "cess": 0,
            "total_tax": 0,
        }
    )

    for item in items:
        hsn = item.get("hsn_code") or "NA"
        entry = hsn_map[hsn]
        entry["hsn_code"] = hsn
        entry["total_quantity"] += item.get("quantity", 0)
        entry["taxable_value"] += item.get("taxable_amount", 0)
        entry["cgst"] += item.get("cgst_amount") or 0
        entry["sgst"] += item.get("sgst_amount") or 0
        entry["igst"] += item.get("igst_amount") or 0
        entry["cess"] += item.get("cess_amount") or 0
        entry["total_tax"] += item.get("total_tax") or 0

    return list(hsn_map.values())


def _number_to_words_inr(amount: float) -> str:
    """
    Convert amount to Indian words.
    e.g. 5430.50 -> 'Rupees Five Thousand Four Hundred Thirty and Fifty Paise Only'
    Simplified version for common amounts.
    """
    ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven",
            "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen",
            "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty",
            "Sixty", "Seventy", "Eighty", "Ninety"]

    def _words(n: int) -> str:
        if n == 0:
            return ""
        if n < 20:
            return ones[n]
        if n < 100:
            return tens[n // 10] + (" " + ones[n % 10] if n % 10 else "")
        if n < 1000:
            return ones[n // 100] + " Hundred" + (" " + _words(n % 100) if n % 100 else "")
        if n < 100000:
            return _words(n // 1000) + " Thousand" + (" " + _words(n % 1000) if n % 1000 else "")
        if n < 10000000:
            return _words(n // 100000) + " Lakh" + (" " + _words(n % 100000) if n % 100000 else "")
        return _words(n // 10000000) + " Crore" + (" " + _words(n % 10000000) if n % 10000000 else "")

    rupees = int(amount)
    paise = round((amount - rupees) * 100)

    result = "Rupees " + (_words(rupees) if rupees else "Zero")
    if paise:
        result += f" and {_words(paise)} Paise"
    result += " Only"
    return result


class InvoiceService:
    def __init__(self, db: AsyncIOMotorDatabase, org_slug: str):
        self.db = db
        self.org_slug = org_slug
        self.invoices = get_tenant_collection(db, org_slug, "invoices")
        self.sales = get_tenant_collection(db, org_slug, "sales")
        self.customers = get_tenant_collection(db, org_slug, "customers")

    # ── Invoice number generation ────────────────────────────────

    async def _generate_number(self, invoice_type: str) -> str:
        """
        Generate sequential invoice number per type and financial year.
        Format: {PREFIX}-{FY}-{SEQUENCE}
        e.g. TI-2526-0001, CN-2526-0002
        """
        prefix = PREFIX_MAP.get(invoice_type, "INV")
        fy = _get_fy_code()
        series = f"{prefix}-{fy}-"

        last = await self.invoices.find_one(
            {"invoice_number": {"$regex": f"^{series}"}},
            sort=[("invoice_number", -1)],
        )
        if last:
            last_seq = int(last["invoice_number"].split("-")[-1])
            return f"{series}{str(last_seq + 1).zfill(4)}"
        return f"{series}0001"

    # ── Create Invoice ───────────────────────────────────────────

    async def create_invoice(self, data: dict, created_by: str | None = None) -> dict:
        """
        Create a new invoice, credit note, quotation, or challan.
        Auto-generates invoice number and HSN summary if not provided.
        Auto-generates amount_in_words if not provided.
        """
        now = datetime.now(timezone.utc)
        inv_type = data.get("invoice_type", "tax_invoice")

        # Auto-generate invoice number
        invoice_number = await self._generate_number(inv_type)

        # Auto-generate HSN summary if not provided
        if not data.get("hsn_summary") and data.get("items"):
            data["hsn_summary"] = _build_hsn_summary(data["items"])

        # Auto-generate amount in words
        if not data.get("amount_in_words") and data.get("grand_total"):
            data["amount_in_words"] = _number_to_words_inr(data["grand_total"])

        doc = {
            **data,
            "invoice_number": invoice_number,
            "financial_year": _get_fy_code(),
            "is_deleted": False,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }

        result = await self.invoices.insert_one(doc)
        doc["_id"] = result.inserted_id
        return serialize_mongo_doc(doc)

    # ── Generate from POS Sale ───────────────────────────────────

    async def generate_from_sale(
        self, sale_id: str, extra_data: dict, created_by: str | None = None
    ) -> dict:
        """
        Auto-generate a tax invoice from a completed POS sale.

        Reads the sale document, maps line items to invoice format,
        calculates HSN summary, and creates the invoice.
        """
        if not ObjectId.is_valid(sale_id):
            raise HTTPException(status_code=400, detail="Invalid sale ID")

        sale = await self.sales.find_one(
            {"_id": ObjectId(sale_id), "status": "completed", "is_deleted": {"$ne": True}}
        )
        if not sale:
            raise HTTPException(status_code=404, detail="Completed sale not found")

        # Check if invoice already exists for this sale
        existing = await self.invoices.find_one(
            {"sale_id": sale_id, "is_deleted": {"$ne": True}}
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Invoice already exists for this sale: {existing.get('invoice_number')}",
            )

        # Map sale items to invoice line items
        invoice_items = []
        for i, item in enumerate(sale.get("items", []), 1):
            gst_rate = item.get("gst_rate", 18)
            taxable = item.get("taxable_amount") or item.get("line_total", 0)
            half_rate = gst_rate / 2

            invoice_items.append({
                "sr_no": i,
                "item_id": item.get("item_id"),
                "description": item.get("item_name", ""),
                "hsn_code": item.get("hsn_code"),
                "quantity": item.get("quantity", 0),
                "unit": item.get("unit", "pcs"),
                "unit_price": item.get("unit_price", 0),
                "discount_percent": None,
                "discount_amount": item.get("discount_amount"),
                "taxable_amount": taxable,
                "gst_rate": gst_rate,
                "cgst_rate": half_rate,
                "cgst_amount": item.get("cgst") or round(taxable * half_rate / 100, 2),
                "sgst_rate": half_rate,
                "sgst_amount": item.get("sgst") or round(taxable * half_rate / 100, 2),
                "igst_rate": 0,
                "igst_amount": item.get("igst") or 0,
                "total_tax": item.get("gst_amount") or round(taxable * gst_rate / 100, 2),
                "line_total": item.get("line_total", 0),
            })

        # Build buyer info
        buyer = extra_data.get("buyer")
        if not buyer and sale.get("customer_id"):
            customer = await self.customers.find_one(
                {"_id": ObjectId(sale["customer_id"])}
            )
            if customer:
                buyer = {
                    "name": customer.get("name", ""),
                    "gstin": customer.get("gstin"),
                    "phone": customer.get("phone"),
                    "email": customer.get("email"),
                }
                if customer.get("billing_address"):
                    addr = customer["billing_address"]
                    buyer.update({
                        "address_line1": addr.get("line1"),
                        "city": addr.get("city"),
                        "state": addr.get("state"),
                        "state_code": addr.get("state_code"),
                        "pin_code": addr.get("pin_code"),
                    })

        # Build invoice data
        invoice_data = {
            "invoice_type": "tax_invoice",
            "sale_id": sale_id,
            "seller": extra_data.get("seller", {"name": self.org_slug}),
            "buyer": buyer,
            "items": invoice_items,
            "subtotal": sale.get("subtotal", 0),
            "total_discount": sale.get("total_discount"),
            "taxable_total": sale.get("subtotal", 0),
            "cgst_total": sum(i.get("cgst_amount", 0) for i in invoice_items),
            "sgst_total": sum(i.get("sgst_amount", 0) for i in invoice_items),
            "igst_total": sum(i.get("igst_amount", 0) for i in invoice_items),
            "total_tax": sale.get("total_tax", 0),
            "round_off": sale.get("round_off"),
            "grand_total": sale.get("grand_total", 0),
            "status": "issued",
            "terms_and_conditions": extra_data.get("terms_and_conditions"),
            "bank_details": extra_data.get("bank_details"),
        }

        return await self.create_invoice(invoice_data, created_by)

    # ── Get Invoice ──────────────────────────────────────────────

    async def get_invoice(self, invoice_id: str) -> dict:
        """Get a single invoice by ID with all details."""
        if not ObjectId.is_valid(invoice_id):
            raise HTTPException(status_code=400, detail="Invalid invoice ID")
        doc = await self.invoices.find_one(
            {"_id": ObjectId(invoice_id), "is_deleted": {"$ne": True}}
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Invoice not found")
        return serialize_mongo_doc(doc)

    # ── List Invoices ────────────────────────────────────────────

    async def list_invoices(
        self,
        invoice_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        query: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """List invoices with optional filters (type, status, search, date range)."""
        filters: dict = {"is_deleted": {"$ne": True}}

        if invoice_type:
            filters["invoice_type"] = invoice_type
        if status_filter:
            filters["status"] = status_filter
        if query:
            filters["$or"] = [
                {"invoice_number": {"$regex": query, "$options": "i"}},
                {"buyer.name": {"$regex": query, "$options": "i"}},
                {"buyer.gstin": {"$regex": query, "$options": "i"}},
            ]
        if from_date or to_date:
            date_filter = {}
            if from_date:
                date_filter["$gte"] = from_date
            if to_date:
                date_filter["$lte"] = to_date
            filters["created_at"] = date_filter

        total = await self.invoices.count_documents(filters)
        cursor = self.invoices.find(filters).skip(offset).limit(limit).sort("created_at", -1)
        docs = [serialize_mongo_doc(d) async for d in cursor]
        return docs, total

    # ── Update Invoice ───────────────────────────────────────────

    async def update_invoice(self, invoice_id: str, update_data: dict) -> dict:
        """Update an invoice (only draft or issued status)."""
        if not ObjectId.is_valid(invoice_id):
            raise HTTPException(status_code=400, detail="Invalid invoice ID")

        # Recalculate amount in words if grand_total changed
        if update_data.get("grand_total") and not update_data.get("amount_in_words"):
            update_data["amount_in_words"] = _number_to_words_inr(update_data["grand_total"])

        update_data["updated_at"] = datetime.now(timezone.utc)
        clean = {k: v for k, v in update_data.items() if v is not None}

        result = await self.invoices.find_one_and_update(
            {
                "_id": ObjectId(invoice_id),
                "status": {"$in": ["draft", "issued"]},
                "is_deleted": {"$ne": True},
            },
            {"$set": clean},
            return_document=True,
        )
        if not result:
            raise HTTPException(
                status_code=404, detail="Invoice not found or cannot be updated"
            )
        return serialize_mongo_doc(result)

    # ── Cancel Invoice ───────────────────────────────────────────

    async def cancel_invoice(self, invoice_id: str) -> dict:
        """Cancel an invoice (only draft or issued)."""
        if not ObjectId.is_valid(invoice_id):
            raise HTTPException(status_code=400, detail="Invalid invoice ID")

        result = await self.invoices.find_one_and_update(
            {
                "_id": ObjectId(invoice_id),
                "status": {"$in": ["draft", "issued"]},
                "is_deleted": {"$ne": True},
            },
            {
                "$set": {
                    "status": "cancelled",
                    "cancelled_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            return_document=True,
        )
        if not result:
            raise HTTPException(
                status_code=404, detail="Invoice not found or cannot be cancelled"
            )
        return serialize_mongo_doc(result)
