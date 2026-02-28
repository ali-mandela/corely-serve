from datetime import datetime
from typing import List, Optional
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field, validator
from enum import Enum
from app._models.user import PyObjectId


class PaymentMethod(str, Enum):
    CASH = "cash"
    CARD = "card"
    DIGITAL = "digital"


class PaymentStatus(str, Enum):
    PAID = "paid"
    PENDING = "pending"
    REFUNDED = "refunded"


class SaleItem(BaseModel):
    product_id: PyObjectId = Field(..., description="Reference to Product")
    quantity: int = Field(..., gt=0)
    unit_price: Decimal = Field(..., ge=0)
    discount: Decimal = Field(Decimal('0'), ge=0)
    total: Decimal = Field(..., ge=0)

    @validator('total')
    def calculate_total(cls, v, values):
        if 'quantity' in values and 'unit_price' in values and 'discount' in values:
            calculated_total = (values['quantity'] * values['unit_price']) - values['discount']
            if abs(v - calculated_total) > Decimal('0.01'):  # Allow small rounding differences
                raise ValueError('Total does not match calculated value')
        return v


class Sale(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    invoice_number: str = Field(..., min_length=1, max_length=50, unique=True)
    store_id: PyObjectId = Field(..., description="Reference to Store")
    customer_id: Optional[PyObjectId] = Field(None, description="Reference to Customer")
    employee_id: PyObjectId = Field(..., description="Reference to User/Employee")
    items: List[SaleItem] = Field(..., min_items=1)
    subtotal: Decimal = Field(..., ge=0)
    tax_amount: Decimal = Field(Decimal('0'), ge=0)
    discount_amount: Decimal = Field(Decimal('0'), ge=0)
    total_amount: Decimal = Field(..., ge=0)
    payment_method: PaymentMethod
    payment_status: PaymentStatus = PaymentStatus.PAID
    sale_date: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = Field(None, max_length=500)

    @validator('total_amount')
    def validate_total_amount(cls, v, values):
        if all(key in values for key in ['subtotal', 'tax_amount', 'discount_amount']):
            calculated_total = values['subtotal'] + values['tax_amount'] - values['discount_amount']
            if abs(v - calculated_total) > Decimal('0.01'):  # Allow small rounding differences
                raise ValueError('Total amount does not match calculated value')
        return v

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, Decimal: float}
        json_schema_extra = {
            "example": {
                "invoice_number": "INV-2024-001",
                "store_id": "507f1f77bcf86cd799439012",
                "customer_id": "507f1f77bcf86cd799439013",
                "employee_id": "507f1f77bcf86cd799439014",
                "items": [
                    {
                        "product_id": "507f1f77bcf86cd799439011",
                        "quantity": 2,
                        "unit_price": 24.99,
                        "discount": 0,
                        "total": 49.98
                    }
                ],
                "subtotal": 49.98,
                "tax_amount": 4.37,
                "discount_amount": 0,
                "total_amount": 54.35,
                "payment_method": "card",
                "payment_status": "paid"
            }
        }