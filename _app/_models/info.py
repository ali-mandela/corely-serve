from datetime import datetime
from typing import Optional
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from enum import Enum
from app._models.store import Address
from app._models.user import PyObjectId


class CustomerType(str, Enum):
    RETAIL = "retail"
    BUSINESS = "business"

    # class Address(BaseModel):
    # street: str
    # city: str
    # state: str
    # zip_code: str
    # country: str = "USA"


class InfoModel(BaseModel):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    name: str = Field(..., min_length=1, max_length=100)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    address: Optional[Address] = None
    is_active: bool = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class AppAdminSecrets(BaseModel):
    user_code: str = Field(..., min_length=5, max_length=50)
    temp_password: str = Field(..., min_length=8, max_length=100)
    organization_id: str = Field(..., min_length=5, max_length=50)
