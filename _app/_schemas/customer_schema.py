from typing import List, Optional
from decimal import Decimal
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId
from app._models.customer import CustomerType
from app._models.store import Address


class CustomerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    company: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    address: Optional[Address] = None
    customer_type: CustomerType = CustomerType.RETAIL


class CustomerUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    address: Optional[Address] = None
    customer_type: Optional[CustomerType] = None


class CustomerResponse(BaseModel):
    id: PyObjectId = Field(..., alias="_id")
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[Address] = None
    customer_type: CustomerType
    last_purchase: Optional[str] = None
    total_purchases: Optional[Decimal] = None  # Calculated field
    purchase_count: Optional[int] = None  # Calculated field

    class Config:
        populate_by_name = True
        json_encoders = {Decimal: float}


class CustomerList(BaseModel):
    customers: List[CustomerResponse]
    total: int
    page: int
    per_page: int
    has_next: bool
    has_prev: bool
