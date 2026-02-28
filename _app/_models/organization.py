from datetime import datetime
from typing import Optional, Dict, Any, List
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId


class OrganizationSettings(BaseModel):
    currency: str = "USD"
    timezone: str = "UTC"
    date_format: str = "YYYY-MM-DD"
    tax_rate: float = 0.0
    multi_store_enabled: bool = True
    pos_enabled: bool = True
    inventory_tracking: bool = True
    customer_management: bool = True
    employee_management: bool = True
    reporting_enabled: bool = True


class OrganizationInfo(BaseModel):
    pass


class Organization(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    email: EmailStr
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    website: Optional[str] = None
    logo_url: Optional[str] = None

    # Subscription details
    plan: str = "basic"  # basic, premium, enterprise
    max_stores: int = 1
    max_users: int = 5
    max_products: int = 1000

    # Organization admin
    created_by: PyObjectId
    admin_ids: List[PyObjectId] = Field(default_factory=list)

    site_code: str = Field(..., min_length=3, max_length=20)

    # Settings
    settings: OrganizationSettings = Field(default_factory=OrganizationSettings)
    custom_settings: Dict[str, Any] = Field(default_factory=dict)

    # Status
    is_active: bool = True
    is_verified: bool = False

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "name": "ABC Retail Chain",
                "slug": "abc-retail",
                "description": "Multi-store retail chain specializing in electronics",
                "email": "admin@abcretail.com",
                "phone": "555-123-4567",
                "website": "https://abcretail.com",
                "plan": "premium",
                "max_stores": 10,
                "max_users": 50,
                "max_products": 10000,
                "settings": {
                    "currency": "INR",
                    "timezone": "IST",
                    "tax_rate": 0.08,
                },
            }
        }
