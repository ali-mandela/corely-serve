from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, validator
from enum import Enum


class StoreStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"
    MAINTENANCE = "maintenance"


class StoreType(str, Enum):
    RETAIL = "retail"
    WAREHOUSE = "warehouse"
    OUTLET = "outlet"
    FRANCHISE = "franchise"
    POPUP = "popup"


class Address(BaseModel):
    street: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=1, max_length=100)
    zip_code: Optional[str] = Field(None, min_length=5, max_length=10)
    country: str = Field(default="USA", min_length=2, max_length=100)
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)

    class Config:
        from_attributes = True


class StoreHours(BaseModel):
    monday: Dict[str, Union[str, bool]] = {"open": "09:00", "close": "18:00", "closed": False}
    tuesday: Dict[str, Union[str, bool]] = {"open": "09:00", "close": "18:00", "closed": False}
    wednesday: Dict[str, Union[str, bool]] = {"open": "09:00", "close": "18:00", "closed": False}
    thursday: Dict[str, Union[str, bool]] = {"open": "09:00", "close": "18:00", "closed": False}
    friday: Dict[str, Union[str, bool]] = {"open": "09:00", "close": "18:00", "closed": False}
    saturday: Dict[str, Union[str, bool]] = {"open": "10:00", "close": "16:00", "closed": False}
    sunday: Dict[str, Union[str, bool]] = {"open": "12:00", "close": "16:00", "closed": True}

    class Config:
        from_attributes = True


class StoreSettings(BaseModel):
    currency: str = "USD"
    timezone: str = "UTC"
    tax_rate: float = Field(0.0, ge=0, le=1)
    pos_enabled: bool = True
    inventory_tracking: bool = True
    low_stock_threshold: int = Field(10, ge=0)
    auto_reorder: bool = False
    loyalty_program_enabled: bool = False
    receipt_footer: Optional[str] = None
    custom_fields: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class StoreCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    store_type: StoreType = StoreType.RETAIL
    category: str = Field("general", max_length=50)
    address: Address
    phone: str = Field(..., min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    website: Optional[str] = Field(None, max_length=200)
    manager_id: Optional[str] = None
    store_hours: Optional[StoreHours] = None
    settings: Optional[StoreSettings] = None
    max_employees: int = Field(50, ge=1, le=1000)
    square_footage: Optional[float] = Field(None, gt=0)

    @validator('slug')
    def slug_alphanumeric(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Slug must contain only letters, numbers, hyphens, and underscores')
        return v.lower()


class StoreUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    store_type: Optional[StoreType] = None
    category: Optional[str] = Field(None, max_length=50)
    address: Optional[Address] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    website: Optional[str] = Field(None, max_length=200)
    manager_id: Optional[str] = None
    store_hours: Optional[StoreHours] = None
    status: Optional[StoreStatus] = None
    max_employees: Optional[int] = Field(None, ge=1, le=1000)
    square_footage: Optional[float] = Field(None, gt=0)


class StoreSettingsUpdate(BaseModel):
    currency: Optional[str] = None
    timezone: Optional[str] = None
    tax_rate: Optional[float] = Field(None, ge=0, le=1)
    pos_enabled: Optional[bool] = None
    inventory_tracking: Optional[bool] = None
    low_stock_threshold: Optional[int] = Field(None, ge=0)
    auto_reorder: Optional[bool] = None
    loyalty_program_enabled: Optional[bool] = None
    receipt_footer: Optional[str] = None
    custom_fields: Optional[Dict[str, Any]] = None


class StoreResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    description: Optional[str]
    store_type: StoreType
    category: str
    address: Address
    phone: str
    email: Optional[str]
    website: Optional[str]
    manager_id: Optional[str]
    manager_name: Optional[str]
    store_hours: StoreHours
    settings: StoreSettings
    status: StoreStatus
    max_employees: int
    square_footage: Optional[float]
    total_employees: int
    total_products: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class StoreListResponse(BaseModel):
    stores: List[StoreResponse]
    total: int
    page: int
    per_page: int
    pages: int

    class Config:
        from_attributes = True


class StoreStats(BaseModel):
    store_id: str
    store_name: str
    total_sales: float
    total_orders: int
    total_customers: int
    total_products: int
    total_employees: int
    avg_order_value: float
    monthly_revenue: float
    daily_revenue: float
    inventory_value: float
    low_stock_items: int
    out_of_stock_items: int

    class Config:
        from_attributes = True


class StoreTransfer(BaseModel):
    from_store_id: str
    to_store_id: str
    items: List[Dict[str, Any]]
    notes: Optional[str] = None
    transfer_date: Optional[datetime] = None


class StoreBulkAction(BaseModel):
    store_ids: List[str]
    action: str
    parameters: Optional[Dict[str, Any]] = None