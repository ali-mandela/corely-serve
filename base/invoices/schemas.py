"""
Invoice schemas — GST-compliant for Indian businesses.

Supports:
    - Tax Invoice (standard sale invoice)
    - Credit Note (for returns / adjustments)
    - Quotation / Estimate (pre-sale)
    - Delivery Challan (goods dispatched without invoice)

All invoices follow GST rules:
    - GSTIN of seller and buyer (if registered)
    - HSN-wise tax summary
    - CGST/SGST (intra-state) or IGST (inter-state)
    - Place of supply
    - Reverse charge applicability
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum
from datetime import datetime


# ── Enums ────────────────────────────────────────────────────────


class InvoiceTypeEnum(str, Enum):
    """Types of invoices as per Indian GST law."""
    TAX_INVOICE = "tax_invoice"
    CREDIT_NOTE = "credit_note"
    DEBIT_NOTE = "debit_note"
    QUOTATION = "quotation"
    PROFORMA = "proforma"
    DELIVERY_CHALLAN = "delivery_challan"


class InvoiceStatusEnum(str, Enum):
    DRAFT = "draft"
    ISSUED = "issued"
    PAID = "paid"
    PARTIALLY_PAID = "partially_paid"
    OVERDUE = "overdue"
    CANCELLED = "cancelled"


class GSTTypeEnum(str, Enum):
    CGST_SGST = "cgst_sgst"     # Intra-state (same state)
    IGST = "igst"               # Inter-state (different state)
    EXEMPT = "exempt"
    NIL = "nil"


# ── Sub-models ───────────────────────────────────────────────────


class InvoiceParty(BaseModel):
    """Seller or buyer details on the invoice."""
    name: str = Field(..., min_length=1, max_length=200)
    gstin: Optional[str] = Field(None, max_length=15)
    pan: Optional[str] = Field(None, max_length=10)
    address_line1: Optional[str] = Field(None, max_length=200)
    address_line2: Optional[str] = Field(None, max_length=200)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    state_code: Optional[str] = Field(None, max_length=2)
    pin_code: Optional[str] = Field(None, max_length=6)
    phone: Optional[str] = Field(None, max_length=15)
    email: Optional[str] = Field(None, max_length=100)


class InvoiceLineItem(BaseModel):
    """A single line item on the invoice."""
    sr_no: Optional[int] = None
    item_id: Optional[str] = None
    description: str = Field(..., min_length=1, max_length=300)
    hsn_code: Optional[str] = Field(None, max_length=10)

    # Quantity
    quantity: float = Field(..., gt=0)
    unit: str = Field(default="pcs")
    unit_price: float = Field(..., ge=0, description="Rate per unit excl. tax")

    # Discount
    discount_percent: Optional[float] = Field(None, ge=0, le=100)
    discount_amount: Optional[float] = Field(None, ge=0)

    # Tax
    taxable_amount: float = Field(..., ge=0, description="Amount after discount, before tax")
    gst_rate: float = Field(default=18.0, ge=0, le=28)
    cgst_rate: Optional[float] = Field(None, ge=0)
    cgst_amount: Optional[float] = Field(None, ge=0)
    sgst_rate: Optional[float] = Field(None, ge=0)
    sgst_amount: Optional[float] = Field(None, ge=0)
    igst_rate: Optional[float] = Field(None, ge=0)
    igst_amount: Optional[float] = Field(None, ge=0)
    cess_rate: Optional[float] = Field(None, ge=0)
    cess_amount: Optional[float] = Field(None, ge=0)
    total_tax: float = Field(default=0, ge=0)

    # Line total
    line_total: float = Field(..., ge=0, description="Total incl. tax")


class HSNSummaryItem(BaseModel):
    """
    HSN-wise tax summary — required on GST invoices when total value > 5 lakh.
    Groups items by HSN code and shows aggregate tax.
    """
    hsn_code: str
    description: Optional[str] = None
    uqc: Optional[str] = Field(None, description="Unit Quantity Code (e.g., NOS, KGS)")
    total_quantity: float = Field(..., ge=0)
    taxable_value: float = Field(..., ge=0)
    cgst: Optional[float] = Field(None, ge=0)
    sgst: Optional[float] = Field(None, ge=0)
    igst: Optional[float] = Field(None, ge=0)
    cess: Optional[float] = Field(None, ge=0)
    total_tax: float = Field(..., ge=0)


class BankDetails(BaseModel):
    """Seller's bank details for payment via transfer."""
    account_holder: str
    account_number: str
    bank_name: str
    branch: Optional[str] = None
    ifsc_code: str
    upi_id: Optional[str] = None


# ── Main request schemas ─────────────────────────────────────────


class CreateInvoiceRequest(BaseModel):
    """
    POST /invoices — Create a new invoice.

    Can be created manually or auto-generated from a POS sale.
    """
    # Type
    invoice_type: InvoiceTypeEnum = Field(default=InvoiceTypeEnum.TAX_INVOICE)

    # Reference (if generated from a sale)
    sale_id: Optional[str] = Field(None, description="Link to POS sale")

    # For credit notes — reference original invoice
    original_invoice_id: Optional[str] = Field(None)
    original_invoice_number: Optional[str] = Field(None)

    # Parties
    seller: InvoiceParty
    buyer: Optional[InvoiceParty] = None

    # Place of supply (determines CGST/SGST vs IGST)
    place_of_supply: Optional[str] = Field(None, max_length=100,
        description="State name where goods are delivered")
    place_of_supply_code: Optional[str] = Field(None, max_length=2)
    gst_type: GSTTypeEnum = Field(default=GSTTypeEnum.CGST_SGST)
    reverse_charge: bool = Field(default=False,
        description="Is reverse charge applicable?")

    # Line items
    items: List[InvoiceLineItem] = Field(..., min_length=1)

    # HSN summary (auto-calculated by service if not provided)
    hsn_summary: Optional[List[HSNSummaryItem]] = None

    # Totals
    subtotal: float = Field(..., ge=0)
    total_discount: Optional[float] = Field(None, ge=0)
    taxable_total: float = Field(..., ge=0)
    cgst_total: Optional[float] = Field(None, ge=0)
    sgst_total: Optional[float] = Field(None, ge=0)
    igst_total: Optional[float] = Field(None, ge=0)
    cess_total: Optional[float] = Field(None, ge=0)
    total_tax: float = Field(default=0, ge=0)
    round_off: Optional[float] = None
    grand_total: float = Field(..., ge=0)
    amount_in_words: Optional[str] = Field(None, max_length=300,
        description="Grand total in words (e.g., 'Rupees Five Thousand Only')")

    # Payment
    payment_terms: Optional[str] = Field(None, max_length=200)
    due_date: Optional[datetime] = None
    bank_details: Optional[BankDetails] = None

    # Transport (for delivery challan / e-way bill)
    transport_mode: Optional[str] = Field(None, max_length=50)
    vehicle_number: Optional[str] = Field(None, max_length=20)
    eway_bill_number: Optional[str] = Field(None, max_length=20)

    # Status & notes
    status: InvoiceStatusEnum = Field(default=InvoiceStatusEnum.ISSUED)
    notes: Optional[str] = Field(None, max_length=1000)
    terms_and_conditions: Optional[str] = Field(None, max_length=2000)


class UpdateInvoiceRequest(BaseModel):
    """PUT /invoices/{id} — Update invoice (only draft/issued)."""
    buyer: Optional[InvoiceParty] = None
    items: Optional[List[InvoiceLineItem]] = None
    subtotal: Optional[float] = None
    total_discount: Optional[float] = None
    taxable_total: Optional[float] = None
    cgst_total: Optional[float] = None
    sgst_total: Optional[float] = None
    igst_total: Optional[float] = None
    total_tax: Optional[float] = None
    round_off: Optional[float] = None
    grand_total: Optional[float] = None
    amount_in_words: Optional[str] = None
    payment_terms: Optional[str] = None
    due_date: Optional[datetime] = None
    status: Optional[InvoiceStatusEnum] = None
    notes: Optional[str] = None
    terms_and_conditions: Optional[str] = None


class GenerateFromSaleRequest(BaseModel):
    """POST /invoices/from-sale — Auto-generate invoice from a completed POS sale."""
    sale_id: str = Field(..., description="ID of the completed sale")
    buyer: Optional[InvoiceParty] = Field(None,
        description="Buyer GST details (if registered dealer)")
    terms_and_conditions: Optional[str] = None
    bank_details: Optional[BankDetails] = None
