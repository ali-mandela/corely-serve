from datetime import datetime
from typing import Optional, Dict, Any, List
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId


class Address(BaseModel):
    street: str
    city: str
    state: str
    zip_code: Optional[str] = None
    country: str = "USA"


class StoreHours(BaseModel):
    monday: Dict[str, str] = {"open": "09:00", "close": "18:00"}
    tuesday: Dict[str, str] = {"open": "09:00", "close": "18:00"}
    wednesday: Dict[str, str] = {"open": "09:00", "close": "18:00"}
    thursday: Dict[str, str] = {"open": "09:00", "close": "18:00"}
    friday: Dict[str, str] = {"open": "09:00", "close": "18:00"}
    saturday: Dict[str, str] = {"open": "10:00", "close": "16:00"}
    sunday: Dict[str, str] = {"open": "12:00", "close": "16:00"}


class Store(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organization_id: PyObjectId
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None
    
    # Store category/type
    category: str = "general"  # general, grocery, electronics, clothing, pharmacy, restaurant, etc.
    store_type: str = "retail"  # retail, warehouse, showroom, etc.
    
    # Contact info
    address: Address
    phone: str = Field(..., min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    
    # Management
    manager_id: Optional[PyObjectId] = None
    staff_ids: List[PyObjectId] = Field(default_factory=list)
    
    # Operational settings
    store_hours: StoreHours = Field(default_factory=StoreHours)
    timezone: str = "UTC"
    
    # Configuration
    settings: Dict[str, Any] = Field(default_factory=dict)
    pos_enabled: bool = True
    inventory_enabled: bool = True
    
    # Status
    is_active: bool = True
    is_main_store: bool = False
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "name": "Main Store",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown",
                    "state": "CA",
                    "zip_code": "12345",
                    "country": "USA",
                },
                "phone": "555-123-4567",
                "is_active": True,
                "settings": {"tax_rate": 0.0875, "currency": "USD"},
            }
        }
