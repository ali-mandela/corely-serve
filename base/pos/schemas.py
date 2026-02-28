"""
POS (Point of Sale) schemas — for construction & hardware retail.

Designed for cash-first billing at the counter, with extensible payment
modes (UPI, card, credit) ready when needed.

Flow:
    1. Cashier creates a sale with line items
    2. GST is auto-calculated per line item
    3. Payment is recorded (cash now, others later)
    4. Stock is auto-deducted via inventory movements
    5. Invoice number is auto-generated
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum
from datetime import datetime


# ── Enums ────────────────────────────────────────────────────────


class SaleStatusEnum(str, Enum):
    """Lifecycle of a sale."""
    DRAFT = "draft"                 # Bill being prepared (items being added)
    COMPLETED = "completed"         # Payment received, stock deducted
    ON_HOLD = "on_hold"             # Parked for later (customer will return)
    CANCELLED = "cancelled"         # Voided before payment
    RETURNED = "returned"           # Full return / credit note issued


class PaymentModeEnum(str, Enum):
    """Payment methods — cash is primary, others are extensible."""
    CASH = "cash"
    UPI = "upi"                     # Google Pay, PhonePe, Paytm, etc.
    CARD = "card"                   # Debit / Credit card
    CREDIT = "credit"               # Customer credit account (khata)
    BANK_TRANSFER = "bank_transfer" # NEFT / RTGS / IMPS
    CHEQUE = "cheque"
    MIXED = "mixed"                 # Split payment (part cash + part UPI etc.)
    OTHER = "other"


class DiscountTypeEnum(str, Enum):
    PERCENTAGE = "percentage"
    FLAT = "flat"                   # Fixed INR amount


class ReturnReasonEnum(str, Enum):
    DEFECTIVE = "defective"
    WRONG_ITEM = "wrong_item"
    CUSTOMER_CHANGED_MIND = "customer_changed_mind"
    EXCESS_QUANTITY = "excess_quantity"
    DAMAGED = "damaged"
    OTHER = "other"


# ── Sub-models ───────────────────────────────────────────────────


class SaleLineItem(BaseModel):
    """A single item in the bill."""
    item_id: str = Field(..., description="Reference to items collection")
    item_name: str = Field(..., min_length=1, max_length=200)
    sku: Optional[str] = None
    hsn_code: Optional[str] = Field(None, max_length=10)

    # Quantity & unit
    quantity: float = Field(..., gt=0)
    unit: str = Field(default="pcs")

    # Pricing
    unit_price: float = Field(..., ge=0, description="Selling price per unit (excl. tax)")
    mrp: Optional[float] = Field(None, ge=0)

    # Discount (per line item)
    discount_type: Optional[DiscountTypeEnum] = None
    discount_value: Optional[float] = Field(None, ge=0)
    discount_amount: Optional[float] = Field(None, ge=0, description="Calculated discount in INR")

    # GST
    gst_rate: float = Field(default=18.0, ge=0, le=28, description="GST % slab")
    gst_amount: Optional[float] = Field(None, ge=0, description="Calculated GST amount")
    cgst: Optional[float] = Field(None, ge=0)
    sgst: Optional[float] = Field(None, ge=0)
    igst: Optional[float] = Field(None, ge=0)

    # Line total
    taxable_amount: Optional[float] = Field(None, ge=0, description="Price after discount, before tax")
    line_total: float = Field(..., ge=0, description="Final line total incl. tax")


class PaymentDetail(BaseModel):
    """
    Payment record for a sale.
    For cash-only, there's one entry. For mixed, there can be multiple.
    """
    mode: PaymentModeEnum = Field(default=PaymentModeEnum.CASH)
    amount: float = Field(..., ge=0)
    reference: Optional[str] = Field(None, max_length=100,
        description="UPI txn ID, cheque no., card last 4 digits, etc.")
    notes: Optional[str] = Field(None, max_length=200)


# ── Main request schemas ─────────────────────────────────────────


class CreateSaleRequest(BaseModel):
    """
    POST /pos/sales — Create a new sale / bill.

    The cashier adds line items, applies discounts, and records payment.
    On completion, stock is auto-deducted from inventory.
    """

    # Customer (optional — walk-in customers don't need this)
    customer_id: Optional[str] = Field(None, description="Link to customers collection")
    customer_name: Optional[str] = Field(None, max_length=200, description="Walk-in name or registered")
    customer_phone: Optional[str] = Field(None, max_length=15)

    # Line items
    items: List[SaleLineItem] = Field(..., min_length=1)

    # Bill-level discount
    bill_discount_type: Optional[DiscountTypeEnum] = None
    bill_discount_value: Optional[float] = Field(None, ge=0)
    bill_discount_amount: Optional[float] = Field(None, ge=0, description="Calculated bill discount")

    # Totals (frontend calculates, backend verifies)
    subtotal: float = Field(..., ge=0, description="Sum of all line totals before bill discount")
    total_discount: Optional[float] = Field(None, ge=0, description="Total discount (item + bill)")
    total_tax: float = Field(default=0, ge=0, description="Total GST amount")
    round_off: Optional[float] = Field(None, description="Round off (+/-)")
    grand_total: float = Field(..., ge=0, description="Final amount customer pays")

    # Payment
    payments: List[PaymentDetail] = Field(
        default_factory=lambda: [PaymentDetail(mode=PaymentModeEnum.CASH, amount=0)],
        description="One or more payment entries. Default is cash."
    )
    amount_received: Optional[float] = Field(None, ge=0, description="Cash received from customer")
    change_due: Optional[float] = Field(None, ge=0, description="Change to return")

    # Status
    status: SaleStatusEnum = Field(default=SaleStatusEnum.COMPLETED)

    # Notes
    notes: Optional[str] = Field(None, max_length=500)


class HoldSaleRequest(BaseModel):
    """PUT /pos/sales/{id}/hold — Park a bill for later."""
    reason: Optional[str] = Field(None, max_length=200)


class CompleteSaleRequest(BaseModel):
    """PUT /pos/sales/{id}/complete — Complete a held/draft sale with payment."""
    payments: List[PaymentDetail] = Field(..., min_length=1)
    amount_received: Optional[float] = Field(None, ge=0)
    change_due: Optional[float] = Field(None, ge=0)


class SaleReturnItem(BaseModel):
    """Single item being returned from a completed sale."""
    item_id: str
    item_name: Optional[str] = None
    quantity: float = Field(..., gt=0, description="Quantity being returned")
    unit_price: float = Field(..., ge=0)
    line_total: float = Field(..., ge=0, description="Refund amount for this line")
    reason: Optional[str] = None


class SaleReturnRequest(BaseModel):
    """
    POST /pos/sales/{id}/return — Return items from a completed sale.
    Creates a credit note and adds stock back via inventory movements.
    """
    items: List[SaleReturnItem] = Field(..., min_length=1)
    reason: ReturnReasonEnum
    notes: Optional[str] = Field(None, max_length=500)
    refund_mode: PaymentModeEnum = Field(default=PaymentModeEnum.CASH)
    refund_amount: float = Field(..., ge=0)
