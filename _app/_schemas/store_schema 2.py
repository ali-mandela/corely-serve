from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from app.models.user import PyObjectId
from app.models.store import Address, StoreHours


class StoreCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    category: str = "general"
    store_type: str = "retail"
    address: Address
    phone: str = Field(..., min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    manager_id: Optional[str] = None
    store_hours: Optional[StoreHours] = None
    timezone: str = "UTC"
    settings: Dict[str, Any] = Field(default_factory=dict)


class StoreUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    category: Optional[str] = None
    store_type: Optional[str] = None
    address: Optional[Address] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    manager_id: Optional[str] = None
    store_hours: Optional[StoreHours] = None
    timezone: Optional[str] = None
    is_active: Optional[bool] = None
    pos_enabled: Optional[bool] = None
    inventory_enabled: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None


class StoreResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    description: Optional[str]
    category: str
    store_type: str
    address: Address
    phone: str
    email: Optional[str]
    manager_id: Optional[str]
    staff_ids: List[str]
    store_hours: StoreHours
    timezone: str
    settings: Dict[str, Any]
    pos_enabled: bool
    inventory_enabled: bool
    is_active: bool
    is_main_store: bool
    created_at: str
    updated_at: str
    manager_name: Optional[str] = None  # Populated via join
    employee_count: Optional[int] = None  # Calculated field
    total_inventory_value: Optional[float] = None  # Calculated field
    today_sales_count: Optional[int] = None  # Calculated field
    today_sales_amount: Optional[float] = None  # Calculated field

    class Config:
        populate_by_name = True


class StoreList(BaseModel):
    stores: List[StoreResponse]
    total: int
    active_count: int
    inactive_count: int
    page: int
    per_page: int
    has_next: bool
    has_prev: bool


class StoreSettings(BaseModel):
    tax_rate: Optional[float] = Field(None, ge=0, le=1)
    currency: Optional[str] = Field("USD", max_length=3)
    timezone: Optional[str] = Field("UTC", max_length=50)
    business_hours: Optional[Dict[str, Any]] = None
    receipt_footer: Optional[str] = Field(None, max_length=500)
    low_stock_threshold: Optional[int] = Field(10, ge=0)
    auto_reorder: Optional[bool] = False
    loyalty_points_rate: Optional[float] = Field(
        0.01, ge=0, le=1
    )  # Points per dollar spent


class StoreTransfer(BaseModel):
    product_id: PyObjectId
    from_store_id: PyObjectId
    to_store_id: PyObjectId
    quantity: int = Field(..., gt=0)
    reason: str = Field(..., min_length=1, max_length=200)
    notes: Optional[str] = Field(None, max_length=500)


class StoreStats(BaseModel):
    store_id: PyObjectId
    store_name: str
    total_products: int
    total_inventory_value: float
    low_stock_items: int
    out_of_stock_items: int
    today_sales: Dict[str, Any]
    this_week_sales: Dict[str, Any]
    this_month_sales: Dict[str, Any]
    top_products: List[Dict[str, Any]]
    employee_count: int
