from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId
from app._models.store import Address


class ContactPerson(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    title: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=15)


class Supplier(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    name: str = Field(..., min_length=1, max_length=200)
    supplier_code: str = Field(..., min_length=1, max_length=20, unique=True)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=15)
    website: Optional[str] = Field(None, max_length=200)
    address: Optional[Address] = None
    contact_persons: List[ContactPerson] = Field(default_factory=list)
    tax_id: Optional[str] = Field(None, max_length=50)
    payment_terms: Optional[str] = Field(None, max_length=100)  # e.g., "Net 30", "COD"
    credit_limit: Optional[float] = Field(None, ge=0)
    categories: List[str] = Field(default_factory=list)  # Product categories supplied
    is_active: bool = True
    notes: Optional[str] = Field(None, max_length=1000)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_order_date: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "name": "ABC Hardware Supply Co.",
                "supplier_code": "SUP001",
                "email": "orders@abchardware.com",
                "phone": "555-111-2222",
                "website": "www.abchardware.com",
                "address": {
                    "street": "789 Industrial Blvd",
                    "city": "Warehouse City",
                    "state": "TX",
                    "zip_code": "75201",
                    "country": "USA"
                },
                "contact_persons": [
                    {
                        "name": "Mike Johnson",
                        "title": "Sales Manager",
                        "email": "mike@abchardware.com",
                        "phone": "555-111-2223"
                    }
                ],
                "payment_terms": "Net 30",
                "credit_limit": 50000,
                "categories": ["Tools", "Hardware", "Fasteners"],
                "is_active": True
            }
        }