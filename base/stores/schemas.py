"""
Store / Branch / Location schemas — for multi-location inventory management.

Supports:
    - Main shop / showroom
    - Branches in other areas/cities
    - Godowns / warehouses for bulk storage
    - Construction site locations (temporary)
    - Stock transfers between any two locations
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum
import re


class StoreTypeEnum(str, Enum):
    SHOP = "shop"                   # Main retail counter
    BRANCH = "branch"               # Another retail location
    GODOWN = "godown"               # Warehouse / storage
    SITE = "site"                   # Construction site (temporary)


class StoreStatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    TEMPORARILY_CLOSED = "temporarily_closed"


class TransferStatusEnum(str, Enum):
    PENDING = "pending"             # Transfer initiated, not yet received
    IN_TRANSIT = "in_transit"       # Goods dispatched
    RECEIVED = "received"           # Goods received at destination
    CANCELLED = "cancelled"


class StoreAddress(BaseModel):
    """Address of the store/branch/godown."""
    line1: str = Field(..., min_length=1, max_length=200)
    line2: Optional[str] = Field(None, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=1, max_length=100)
    pin_code: str = Field(..., min_length=6, max_length=6)
    landmark: Optional[str] = Field(None, max_length=200)

    @field_validator("pin_code")
    @classmethod
    def validate_pin(cls, v):
        if not v.isdigit() or len(v) != 6:
            raise ValueError("PIN code must be exactly 6 digits")
        return v


class StoreContact(BaseModel):
    """Contact person for the store/branch."""
    name: str = Field(..., min_length=1, max_length=100)
    phone: str = Field(..., max_length=15)
    email: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field(None, max_length=50, description="e.g. Store Manager, Godown Keeper")


class CreateStoreRequest(BaseModel):
    """POST /stores — Create a new store, branch, or godown."""
    name: str = Field(..., min_length=2, max_length=150)
    code: str = Field(..., min_length=2, max_length=20,
        description="Short unique code, e.g. MAIN, BR-01, GD-NORTH")
    store_type: StoreTypeEnum = Field(default=StoreTypeEnum.SHOP)
    status: StoreStatusEnum = Field(default=StoreStatusEnum.ACTIVE)

    address: StoreAddress
    contact: Optional[StoreContact] = None

    # Operations
    gstin: Optional[str] = Field(None, max_length=15, description="Separate GSTIN if registered")
    manager_user_id: Optional[str] = Field(None, description="Assigned manager from users")
    is_default: bool = Field(default=False, description="Is this the main/primary store?")

    # Business hours
    opening_time: Optional[str] = Field(None, max_length=10, description="e.g. 09:00")
    closing_time: Optional[str] = Field(None, max_length=10, description="e.g. 21:00")
    working_days: Optional[List[str]] = Field(None, description="e.g. ['mon','tue','wed','thu','fri','sat']")

    notes: Optional[str] = Field(None, max_length=500)

    @field_validator("code")
    @classmethod
    def validate_code(cls, v):
        if not re.match(r"^[A-Z0-9\-]+$", v.upper()):
            raise ValueError("Store code must be alphanumeric with hyphens only")
        return v.upper()


class UpdateStoreRequest(BaseModel):
    """PUT /stores/{id} — Update store details."""
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    store_type: Optional[StoreTypeEnum] = None
    status: Optional[StoreStatusEnum] = None
    address: Optional[StoreAddress] = None
    contact: Optional[StoreContact] = None
    gstin: Optional[str] = None
    manager_user_id: Optional[str] = None
    is_default: Optional[bool] = None
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    working_days: Optional[List[str]] = None
    notes: Optional[str] = None


class TransferLineItem(BaseModel):
    """Single item in a stock transfer."""
    item_id: str
    item_name: Optional[str] = None
    sku: Optional[str] = None
    quantity: float = Field(..., gt=0)
    unit: str = Field(default="pcs")
    unit_cost: Optional[float] = Field(None, ge=0)
    notes: Optional[str] = None


class CreateStockTransferRequest(BaseModel):
    """POST /stores/transfers — Transfer stock between two locations."""
    from_store_id: str = Field(..., description="Source store ID")
    to_store_id: str = Field(..., description="Destination store ID")
    items: List[TransferLineItem] = Field(..., min_length=1)
    transport_mode: Optional[str] = Field(None, max_length=50)
    vehicle_number: Optional[str] = Field(None, max_length=20)
    expected_delivery: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = Field(None, max_length=500)


class ReceiveTransferRequest(BaseModel):
    """PUT /stores/transfers/{id}/receive — Confirm receipt of transferred goods."""
    received_items: Optional[List[TransferLineItem]] = Field(None,
        description="If partial receipt, specify items actually received")
    notes: Optional[str] = Field(None, max_length=500)
