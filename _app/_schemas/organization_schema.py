from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId


class Address(BaseModel):
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None

    class Config:
        from_attributes = True


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    email: EmailStr
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    website: Optional[str] = None
    plan: str = "basic"
    address: Address
    allowed_modules: List


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    website: Optional[str] = None
    logo_url: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    custom_settings: Optional[Dict[str, Any]] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    email: EmailStr
    phone: Optional[str]
    website: Optional[str]
    logo_url: Optional[str]
    plan: str
    max_stores: int
    max_users: int
    max_products: int
    owner_id: str
    admin_ids: List[str]
    settings: Dict[str, Any]
    custom_settings: Dict[str, Any]
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class OrganizationSettingsUpdate(BaseModel):
    currency: Optional[str] = None
    timezone: Optional[str] = None
    date_format: Optional[str] = None
    tax_rate: Optional[float] = None
    multi_store_enabled: Optional[bool] = None
    pos_enabled: Optional[bool] = None
    inventory_tracking: Optional[bool] = None
    customer_management: Optional[bool] = None
    employee_management: Optional[bool] = None
    reporting_enabled: Optional[bool] = None


class OrganizationInvite(BaseModel):
    email: EmailStr
    role: str
    store_ids: Optional[List[str]] = None
    message: Optional[str] = None


class OrganizationStats(BaseModel):
    total_stores: int
    total_users: int
    total_products: int
    total_sales: int
    monthly_revenue: float
    active_stores: int
