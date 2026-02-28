"""
Inventory schemas — India-focused, construction & hardware grade.

Covers: stock movements (in/out/adjust/transfer/return), purchase entries
with GST, stock adjustments, and stock queries.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum
from datetime import datetime


# ── Enums ────────────────────────────────────────────────────────


class MovementTypeEnum(str, Enum):
    """Every stock change is one of these types."""
    STOCK_IN = "stock_in"               # Purchase / goods received
    STOCK_OUT = "stock_out"             # Sold via POS or manual issue
    ADJUSTMENT = "adjustment"           # Manual correction (count, damage, expiry)
    TRANSFER_IN = "transfer_in"         # Received from another location
    TRANSFER_OUT = "transfer_out"       # Sent to another location
    RETURN_IN = "return_in"             # Customer returned goods
    RETURN_OUT = "return_out"           # Returned to supplier
    OPENING_STOCK = "opening_stock"     # Initial stock entry


class AdjustmentReasonEnum(str, Enum):
    """Reasons for stock adjustments."""
    PHYSICAL_COUNT = "physical_count"
    DAMAGE = "damage"
    EXPIRED = "expired"
    THEFT_LOSS = "theft_loss"
    SAMPLE = "sample"
    WASTAGE = "wastage"
    CORRECTION = "correction"
    OTHER = "other"


class PurchaseStatusEnum(str, Enum):
    DRAFT = "draft"
    ORDERED = "ordered"
    PARTIALLY_RECEIVED = "partially_received"
    RECEIVED = "received"
    CANCELLED = "cancelled"


class PaymentStatusEnum(str, Enum):
    UNPAID = "unpaid"
    PARTIAL = "partial"
    PAID = "paid"


class PaymentModeEnum(str, Enum):
    CASH = "cash"
    UPI = "upi"
    NEFT_RTGS = "neft_rtgs"
    CHEQUE = "cheque"
    CREDIT = "credit"
    CARD = "card"
    OTHER = "other"


class GSTTypeEnum(str, Enum):
    """GST type on purchase."""
    CGST_SGST = "cgst_sgst"     # Intra-state (same state)
    IGST = "igst"               # Inter-state
    EXEMPT = "exempt"
    NIL = "nil"


# ── Sub-models ───────────────────────────────────────────────────


class GSTBreakdown(BaseModel):
    """GST details on a line item or purchase."""
    hsn_code: Optional[str] = Field(None, max_length=10)
    gst_rate: float = Field(default=18.0, ge=0, le=28)
    gst_type: GSTTypeEnum = Field(default=GSTTypeEnum.CGST_SGST)
    taxable_amount: float = Field(..., ge=0)
    cgst: Optional[float] = Field(None, ge=0)
    sgst: Optional[float] = Field(None, ge=0)
    igst: Optional[float] = Field(None, ge=0)
    cess: Optional[float] = Field(None, ge=0)
    total_tax: float = Field(..., ge=0)
    total_with_tax: float = Field(..., ge=0)


class PurchaseLineItem(BaseModel):
    """Single item line in a purchase entry."""
    item_id: str = Field(..., description="Reference to items collection")
    item_name: str = Field(..., min_length=1, max_length=200)
    sku: Optional[str] = None
    hsn_code: Optional[str] = Field(None, max_length=10)

    # Quantity
    quantity: float = Field(..., gt=0)
    received_qty: Optional[float] = Field(None, ge=0, description="Actual received (if different)")
    unit: str = Field(default="pcs")

    # Pricing
    unit_price: float = Field(..., ge=0, description="Price per unit excl. tax")
    discount_percent: Optional[float] = Field(None, ge=0, le=100)
    discount_amount: Optional[float] = Field(None, ge=0)

    # GST
    gst_rate: float = Field(default=18.0, ge=0, le=28)
    gst_amount: Optional[float] = Field(None, ge=0)
    line_total: float = Field(..., ge=0, description="Final line total incl. tax")

    # Batch / expiry (for items that need it)
    batch_number: Optional[str] = Field(None, max_length=50)
    manufacture_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None


class SupplierInfo(BaseModel):
    """Supplier details on a purchase entry."""
    supplier_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    gstin: Optional[str] = Field(None, min_length=15, max_length=15, description="15-digit GSTIN")
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = Field(None, description="State name — needed for CGST/SGST vs IGST")
    state_code: Optional[str] = Field(None, max_length=2, description="2-digit state code")

    @field_validator("gstin")
    @classmethod
    def validate_gstin(cls, v):
        if v:
            import re
            pattern = r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$"
            if not re.match(pattern, v.upper()):
                raise ValueError("Invalid GSTIN format")
            return v.upper()
        return v


# ── Main request schemas ─────────────────────────────────────────


class StockMovementRequest(BaseModel):
    """
    Record a stock movement — this is the core of inventory tracking.
    Every stock change (in/out/adjust/transfer) creates one of these.
    """
    item_id: str = Field(..., description="Item ObjectId")
    item_name: Optional[str] = Field(None, max_length=200)
    sku: Optional[str] = None

    movement_type: MovementTypeEnum
    quantity: float = Field(..., gt=0, description="Quantity moved (always positive)")
    unit: str = Field(default="pcs")

    # Reference (links to purchase, POS sale, adjustment, etc.)
    reference_type: Optional[str] = Field(None, description="purchase, sale, adjustment, transfer")
    reference_id: Optional[str] = Field(None, description="ID of the related document")

    # Pricing context
    unit_cost: Optional[float] = Field(None, ge=0, description="Cost per unit at this movement")

    # Location
    from_location: Optional[str] = Field(None, max_length=100)
    to_location: Optional[str] = Field(None, max_length=100)

    # Batch
    batch_number: Optional[str] = None

    # Reason (for adjustments)
    reason: Optional[AdjustmentReasonEnum] = None
    notes: Optional[str] = Field(None, max_length=500)


class PurchaseEntryRequest(BaseModel):
    """
    Record a purchase / goods received note (GRN).
    Creates stock_in movements automatically for each line item.
    """
    # Supplier
    supplier: SupplierInfo

    # Invoice details
    invoice_number: Optional[str] = Field(None, max_length=50)
    invoice_date: Optional[datetime] = None
    challan_number: Optional[str] = Field(None, max_length=50, description="Delivery challan no.")
    po_number: Optional[str] = Field(None, max_length=50, description="Purchase order no.")

    # Items
    items: List[PurchaseLineItem] = Field(..., min_length=1)

    # Totals
    subtotal: float = Field(..., ge=0, description="Sum of line totals before tax")
    total_discount: Optional[float] = Field(None, ge=0)
    total_gst: float = Field(default=0, ge=0)
    round_off: Optional[float] = Field(None, description="Round off amount (+/-)")
    grand_total: float = Field(..., ge=0, description="Final payable amount")

    # GST summary
    gst_type: GSTTypeEnum = Field(default=GSTTypeEnum.CGST_SGST)
    cgst_total: Optional[float] = Field(None, ge=0)
    sgst_total: Optional[float] = Field(None, ge=0)
    igst_total: Optional[float] = Field(None, ge=0)

    # Payment
    payment_status: PaymentStatusEnum = Field(default=PaymentStatusEnum.UNPAID)
    payment_mode: Optional[PaymentModeEnum] = None
    amount_paid: Optional[float] = Field(None, ge=0)

    # Transport / logistics
    transport_charges: Optional[float] = Field(None, ge=0)
    transporter_name: Optional[str] = None
    vehicle_number: Optional[str] = None
    eway_bill_number: Optional[str] = Field(None, max_length=20, description="E-way bill for goods > 50k")

    # Status
    status: PurchaseStatusEnum = Field(default=PurchaseStatusEnum.RECEIVED)
    notes: Optional[str] = Field(None, max_length=1000)
    received_by: Optional[str] = None
    received_at_location: Optional[str] = Field(None, max_length=100)


class StockAdjustmentRequest(BaseModel):
    """Manual stock adjustment with reason tracking."""
    item_id: str
    item_name: Optional[str] = None
    sku: Optional[str] = None

    adjustment_type: str = Field(
        ..., description="'increase' or 'decrease'"
    )
    quantity: float = Field(..., gt=0)
    unit: str = Field(default="pcs")

    reason: AdjustmentReasonEnum
    notes: Optional[str] = Field(None, max_length=500)
    location: Optional[str] = Field(None, max_length=100)

    @field_validator("adjustment_type")
    @classmethod
    def validate_type(cls, v):
        if v not in ("increase", "decrease"):
            raise ValueError("adjustment_type must be 'increase' or 'decrease'")
        return v


class StockQueryParams(BaseModel):
    """Query parameters for stock reports."""
    item_id: Optional[str] = None
    category: Optional[str] = None
    low_stock_only: bool = False
    location: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
