from pydantic import BaseModel, EmailStr, constr, Field, HttpUrl, validator
from typing import Optional, List
from enum import Enum
from datetime import datetime, timezone
from bson import ObjectId
from .common_schema import Address


class RoleEnum(str, Enum):
    ADMIN = "admin"
    EMPLOYEE = "employee"


class Employee(BaseModel):
    employee_id: constr(strip_whitespace=True, min_length=3, max_length=50) = Field(
        ..., description="Unique employee identifier"
    )
    name: constr(strip_whitespace=True, min_length=2, max_length=100) = Field(
        ..., description="Full name of the employee"
    )
    username: constr(strip_whitespace=True, min_length=3, max_length=50) = Field(
        ..., description="Username for login"
    )
    email: EmailStr = Field(..., description="Official email address")
    phone: constr(strip_whitespace=True, min_length=10, max_length=15) = Field(
        ..., description="Contact phone number"
    )
    address: Address = Field(..., description="Residential or work address")
    designation: Optional[str] = Field(None, description="Job title or position")
    profile_pic: Optional[HttpUrl] = Field(None, description="Profile picture URL")

    joining_date: datetime = Field(
        default_factory=lambda: datetime.now(datetime.timezone.utc),
        description="Employee joining date",
    )
    stores: Optional[List[str]] = Field(
        default_factory=list,
        description="List of store IDs associated with the employee",
    )
    is_active: bool = Field(default=True, description="Is employee active")
    is_deleted: bool = Field(default=False, description="Is employee deleted")

    role: RoleEnum = Field("EMPLOYEE", description="Role of employee in system")
    permissions: Optional[List[str]] = Field(
        default_factory=list,
        description="List of permission codes like ['A1', 'B2', 'D3']",
    )

    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Record creation timestamp"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Last record update timestamp"
    )
    password: str

    @validator("phone")
    def validate_phone(cls, v):
        import re

        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not cleaned.replace("+", "").isdigit():
            raise ValueError("Invalid phone number format")
        return cleaned

    class Config:
        anystr_strip_whitespace = True
        json_encoders = {ObjectId: str}
