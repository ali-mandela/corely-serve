"""
Vendor / Supplier schemas — India-focused for construction & hardware supply chain.
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List
from enum import Enum
import re


class VendorTypeEnum(str, Enum):
    MANUFACTURER = "manufacturer"
    DISTRIBUTOR = "distributor"
    WHOLESALER = "wholesaler"
    DEALER = "dealer"
    IMPORTER = "importer"
    LOCAL_SUPPLIER = "local_supplier"
    TRANSPORTER = "transporter"
    CONTRACTOR = "contractor"
    OTHER = "other"


class VendorStatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BLACKLISTED = "blacklisted"
    ON_HOLD = "on_hold"


class PaymentTermEnum(str, Enum):
    ADVANCE = "advance"
    CASH = "cash"
    CREDIT_7 = "credit_7"
    CREDIT_15 = "credit_15"
    CREDIT_30 = "credit_30"
    CREDIT_45 = "credit_45"
    CREDIT_60 = "credit_60"
    CREDIT_90 = "credit_90"
    COD = "cod"


class AddressModel(BaseModel):
    line1: str = Field(..., min_length=3, max_length=200)
    line2: Optional[str] = Field(None, max_length=200)
    city: str = Field(..., min_length=2, max_length=100)
    district: Optional[str] = Field(None, max_length=100)
    state: str = Field(..., min_length=2, max_length=100)
    state_code: Optional[str] = Field(None, max_length=2)
    pin_code: str = Field(..., min_length=6, max_length=6)
    country: str = Field(default="India")

    @field_validator("pin_code")
    @classmethod
    def validate_pin(cls, v):
        if not v.isdigit() or len(v) != 6:
            raise ValueError("PIN code must be exactly 6 digits")
        return v


class BankDetailsModel(BaseModel):
    """Vendor bank details for payments."""
    account_holder: str = Field(..., min_length=2, max_length=100)
    account_number: str = Field(..., min_length=5, max_length=20)
    bank_name: str = Field(..., min_length=2, max_length=100)
    branch: Optional[str] = Field(None, max_length=100)
    ifsc_code: str = Field(..., min_length=11, max_length=11)
    upi_id: Optional[str] = Field(None, max_length=50)

    @field_validator("ifsc_code")
    @classmethod
    def validate_ifsc(cls, v):
        if not re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", v.upper()):
            raise ValueError("Invalid IFSC code format (e.g. SBIN0001234)")
        return v.upper()


class ContactPerson(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    phone: str = Field(..., min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    designation: Optional[str] = Field(None, max_length=50)


class CreateVendorRequest(BaseModel):
    """POST /vendors"""

    # Identity
    name: str = Field(..., min_length=2, max_length=200, description="Business / vendor name")
    display_name: Optional[str] = Field(None, max_length=100, description="Short name")
    phone: str = Field(..., min_length=10, max_length=15)
    alt_phone: Optional[str] = Field(None, max_length=15)
    email: Optional[EmailStr] = None
    website: Optional[str] = Field(None, max_length=200)

    # Classification
    vendor_type: VendorTypeEnum = Field(default=VendorTypeEnum.LOCAL_SUPPLIER)
    categories_supplied: Optional[List[str]] = Field(
        default=[], description="Item categories this vendor supplies"
    )
    tags: Optional[List[str]] = Field(default=[])

    # Address
    address: Optional[AddressModel] = None

    # GST / Tax (India)
    gstin: Optional[str] = Field(None, min_length=15, max_length=15)
    pan: Optional[str] = Field(None, min_length=10, max_length=10)
    msme_number: Optional[str] = Field(None, max_length=20, description="MSME/Udyam registration")
    tds_applicable: bool = Field(default=False)
    tds_rate: Optional[float] = Field(None, ge=0, le=30, description="TDS deduction rate %")

    # Payment
    payment_term: PaymentTermEnum = Field(default=PaymentTermEnum.CREDIT_30)
    credit_limit: Optional[float] = Field(None, ge=0, description="Max credit (INR)")
    outstanding_balance: Optional[float] = Field(default=0)
    bank_details: Optional[BankDetailsModel] = None

    # Contacts
    contact_persons: Optional[List[ContactPerson]] = Field(default=[])

    # Lead time
    avg_lead_time_days: Optional[int] = Field(None, ge=0, description="Avg delivery days")
    min_order_value: Optional[float] = Field(None, ge=0, description="Minimum order value (INR)")

    # Status
    status: VendorStatusEnum = Field(default=VendorStatusEnum.ACTIVE)
    notes: Optional[str] = Field(None, max_length=1000)

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


class UpdateVendorRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=200)
    display_name: Optional[str] = None
    phone: Optional[str] = None
    alt_phone: Optional[str] = None
    email: Optional[EmailStr] = None
    website: Optional[str] = None
    vendor_type: Optional[VendorTypeEnum] = None
    categories_supplied: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    address: Optional[AddressModel] = None
    gstin: Optional[str] = None
    pan: Optional[str] = None
    msme_number: Optional[str] = None
    tds_applicable: Optional[bool] = None
    tds_rate: Optional[float] = None
    payment_term: Optional[PaymentTermEnum] = None
    credit_limit: Optional[float] = None
    bank_details: Optional[BankDetailsModel] = None
    contact_persons: Optional[List[ContactPerson]] = None
    avg_lead_time_days: Optional[int] = None
    min_order_value: Optional[float] = None
    status: Optional[VendorStatusEnum] = None
    notes: Optional[str] = None
