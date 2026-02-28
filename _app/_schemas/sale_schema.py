from typing import List, Optional
from decimal import Decimal
from datetime import datetime
from pydantic import BaseModel, Field, validator
from app._models.user import PyObjectId
from app._models.sale import PaymentMethod, PaymentStatus


class SaleItemCreate(BaseModel):
    product_id: PyObjectId
    quantity: int = Field(..., gt=0)
    unit_price: Decimal = Field(..., ge=0)
    discount: Decimal = Field(Decimal('0'), ge=0)


class SaleCreate(BaseModel):
    store_id: PyObjectId
    customer_id: Optional[PyObjectId] = None
    items: List[SaleItemCreate] = Field(..., min_items=1)
    tax_rate: Decimal = Field(Decimal('0'), ge=0, le=1)  # 0-1 (0-100%)
    discount_amount: Decimal = Field(Decimal('0'), ge=0)
    payment_method: PaymentMethod
    notes: Optional[str] = Field(None, max_length=500)


class SaleItemResponse(BaseModel):
    product_id: PyObjectId
    quantity: int
    unit_price: Decimal
    discount: Decimal
    total: Decimal
    product_name: Optional[str] = None  # Populated via join
    product_sku: Optional[str] = None   # Populated via join

    class Config:
        json_encoders = {Decimal: float}


class SaleResponse(BaseModel):
    id: PyObjectId = Field(..., alias="_id")
    invoice_number: str
    store_id: PyObjectId
    customer_id: Optional[PyObjectId] = None
    employee_id: PyObjectId
    items: List[SaleItemResponse]
    subtotal: Decimal
    tax_amount: Decimal
    discount_amount: Decimal
    total_amount: Decimal
    payment_method: PaymentMethod
    payment_status: PaymentStatus
    sale_date: str
    notes: Optional[str] = None
    store_name: Optional[str] = None     # Populated via join
    customer_name: Optional[str] = None  # Populated via join
    employee_name: Optional[str] = None  # Populated via join

    class Config:
        populate_by_name = True
        json_encoders = {Decimal: float}


class SaleList(BaseModel):
    sales: List[SaleResponse]
    total: int
    page: int
    per_page: int
    total_amount: Decimal
    has_next: bool
    has_prev: bool

    class Config:
        json_encoders = {Decimal: float}


class SaleReturn(BaseModel):
    sale_id: PyObjectId
    items: List[dict]  # List of items to return with quantities
    reason: str = Field(..., min_length=1, max_length=200)
    refund_amount: Decimal = Field(..., ge=0)


class SalesReport(BaseModel):
    period_start: str
    period_end: str
    total_sales: int
    total_amount: Decimal
    average_sale_amount: Decimal
    top_products: List[dict]
    sales_by_payment_method: dict
    sales_by_store: Optional[dict] = None

    class Config:
        json_encoders = {Decimal: float}