"""
Customer schemas — India-focused for construction & hardware.
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List
from enum import Enum
import re


class CustomerTypeEnum(str, Enum):
    INDIVIDUAL = "individual"
    CONTRACTOR = "contractor"
    BUILDER = "builder"
    DEALER = "dealer"
    GOVERNMENT = "government"
    INSTITUTIONAL = "institutional"
    WHOLESALE = "wholesale"
    RETAIL = "retail"
    OTHER = "other"


class PaymentTermEnum(str, Enum):
    CASH = "cash"
    CREDIT_7 = "credit_7"
    CREDIT_15 = "credit_15"
    CREDIT_30 = "credit_30"
    CREDIT_45 = "credit_45"
    CREDIT_60 = "credit_60"
    CREDIT_90 = "credit_90"
    ADVANCE = "advance"
    COD = "cod"


class AddressModel(BaseModel):
    line1: str = Field(..., min_length=3, max_length=200)
    line2: Optional[str] = Field(None, max_length=200)
    city: str = Field(..., min_length=2, max_length=100)
    district: Optional[str] = Field(None, max_length=100)
    state: str = Field(..., min_length=2, max_length=100)
    state_code: Optional[str] = Field(None, max_length=2, description="2-digit state code")
    pin_code: str = Field(..., min_length=6, max_length=6)
    country: str = Field(default="India")

    @field_validator("pin_code")
    @classmethod
    def validate_pin(cls, v):
        if not v.isdigit() or len(v) != 6:
            raise ValueError("PIN code must be exactly 6 digits")
        return v


class CreateCustomerRequest(BaseModel):
    """POST /customers"""

    # Identity
    name: str = Field(..., min_length=2, max_length=200)
    phone: str = Field(..., min_length=10, max_length=15)
    alt_phone: Optional[str] = Field(None, max_length=15)
    email: Optional[EmailStr] = None
    company_name: Optional[str] = Field(None, max_length=200)

    # Classification
    customer_type: CustomerTypeEnum = Field(default=CustomerTypeEnum.RETAIL)
    tags: Optional[List[str]] = Field(default=[])

    # Address
    billing_address: Optional[AddressModel] = None
    shipping_address: Optional[AddressModel] = None

    # GST / Tax (India)
    gstin: Optional[str] = Field(None, min_length=15, max_length=15, description="15-digit GSTIN")
    pan: Optional[str] = Field(None, min_length=10, max_length=10, description="PAN card number")

    # Credit / Payment
    payment_term: PaymentTermEnum = Field(default=PaymentTermEnum.CASH)
    credit_limit: Optional[float] = Field(None, ge=0, description="Max credit allowed (INR)")
    outstanding_balance: Optional[float] = Field(default=0, ge=0)

    # Notes
    notes: Optional[str] = Field(None, max_length=1000)
    is_active: bool = True

    @field_validator("phone", "alt_phone")
    @classmethod
    def validate_phone(cls, v):
        if v:
            cleaned = re.sub(r"[\s\-\(\)]", "", v)
            if not cleaned.replace("+", "").isdigit():
                raise ValueError("Invalid phone number")
            return cleaned
        return v

    @field_validator("gstin")
    @classmethod
    def validate_gstin(cls, v):
        if v:
            pattern = r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$"
            if not re.match(pattern, v.upper()):
                raise ValueError("Invalid GSTIN format")
            return v.upper()
        return v

    @field_validator("pan")
    @classmethod
    def validate_pan(cls, v):
        if v:
            pattern = r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$"
            if not re.match(pattern, v.upper()):
                raise ValueError("Invalid PAN format")
            return v.upper()
        return v


class UpdateCustomerRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=200)
    phone: Optional[str] = None
    alt_phone: Optional[str] = None
    email: Optional[EmailStr] = None
    company_name: Optional[str] = None
    customer_type: Optional[CustomerTypeEnum] = None
    tags: Optional[List[str]] = None
    billing_address: Optional[AddressModel] = None
    shipping_address: Optional[AddressModel] = None
    gstin: Optional[str] = None
    pan: Optional[str] = None
    payment_term: Optional[PaymentTermEnum] = None
    credit_limit: Optional[float] = None
    notes: Optional[str] = None
    is_active: Optional[bool] = None
