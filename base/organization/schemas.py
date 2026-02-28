from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import re


class CountryEnum(str, Enum):
    INDIA = "India"
    USA = "United States"
    UK = "United Kingdom"
    CANADA = "Canada"


class AddressModel(BaseModel):
    pin_code: str = Field(..., min_length=4, max_length=10)
    location: Optional[str] = Field(None, max_length=100)
    street: str = Field(..., min_length=5, max_length=200)
    district: str = Field(..., min_length=2, max_length=100)
    state: str = Field(..., min_length=2, max_length=100)
    country: CountryEnum


class ModuleEnum(str, Enum):
    EMPLOYEE_MANAGEMENT = "employee"
    BILLING = "billing"
    ANALYTICS = "analytics"
    NOTIFICATIONS = "notifications"
    REPORTING = "reporting"
    STORES = "stores"
    POS = "pos"
    ALL = "*"


class OrgSetupRequest(BaseModel):
    """Request body for POST /set-up"""
    name: str = Field(..., min_length=3, max_length=100)
    slug: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    address: AddressModel
    owner_email: EmailStr
    owner_name: str = Field(..., min_length=2, max_length=100)
    website: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)
    modules_enabled: List[ModuleEnum] = Field(
        default=[ModuleEnum.EMPLOYEE_MANAGEMENT],
    )

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v):
        if not re.match(r"^[a-z0-9\-]+$", v):
            raise ValueError(
                "Slug must contain only lowercase letters, numbers, and hyphens"
            )
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not cleaned.replace("+", "").isdigit():
            raise ValueError("Invalid phone number format")
        return cleaned


class OrgSetupResponse(BaseModel):
    organization_id: str
    organization_name: str
    slug: str
    admin_user_id: str
    admin_email: str
    temporary_password: str
    setup_completed: bool
    created_at: datetime
    message: str
