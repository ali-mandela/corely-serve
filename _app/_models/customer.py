from datetime import datetime
from typing import Optional
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from enum import Enum
from app._models.user import PyObjectId
from app._models.store import Address


class CustomerType(str, Enum):
    RETAIL = "retail"
    BUSINESS = "business"


class Customer(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    name: str = Field(..., min_length=1, max_length=100)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    address: Optional[Address] = None
    customer_type: CustomerType = CustomerType.RETAIL
    outstanding_balance: Decimal = Field(Decimal("0"), ge=0)
    loyalty_points: int = Field(0, ge=0)
    registration_date: datetime = Field(default_factory=datetime.utcnow)
    last_purchase: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, Decimal: float}
        json_schema_extra = {
            "example": {
                "name": "John Smith",
                "email": "john.smith@email.com",
                "phone": "555-123-4567",
                "address": {
                    "street": "456 Oak St",
                    "city": "Springfield",
                    "state": "IL",
                    "zip_code": "62701",
                    "country": "IND",
                },
                "customer_type": "retail",
                "outstanding_balance": 0,
                "loyalty_points": 150,
            }
        }
