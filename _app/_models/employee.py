from datetime import datetime
from typing import Optional, List
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from app._models.user import PyObjectId, UserRole
from app._models.store import Address


class Employee(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    user_id: Optional[PyObjectId] = Field(None, description="Reference to User if employee has login access")
    employee_id: str = Field(..., min_length=1, max_length=20, unique=True)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    email: Optional[EmailStr] = None
    phone: str = Field(..., min_length=10, max_length=15)
    address: Optional[Address] = None
    position: str = Field(..., min_length=1, max_length=100)
    department: Optional[str] = Field(None, max_length=100)
    store_id: PyObjectId = Field(..., description="Primary store assignment")
    additional_store_ids: List[PyObjectId] = Field(default_factory=list)
    hire_date: datetime = Field(default_factory=datetime.utcnow)
    salary: Optional[Decimal] = Field(None, ge=0)
    hourly_rate: Optional[Decimal] = Field(None, ge=0)
    commission_rate: Decimal = Field(Decimal('0'), ge=0, le=1)  # 0-1 (0-100%)
    is_active: bool = True
    emergency_contact_name: Optional[str] = Field(None, max_length=100)
    emergency_contact_phone: Optional[str] = Field(None, max_length=15)
    notes: Optional[str] = Field(None, max_length=500)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, Decimal: float}
        json_schema_extra = {
            "example": {
                "employee_id": "EMP001",
                "first_name": "Jane",
                "last_name": "Doe",
                "email": "jane.doe@store.com",
                "phone": "555-987-6543",
                "position": "Sales Associate",
                "department": "Sales",
                "store_id": "507f1f77bcf86cd799439012",
                "hourly_rate": 15.50,
                "commission_rate": 0.02,
                "is_active": True
            }
        }