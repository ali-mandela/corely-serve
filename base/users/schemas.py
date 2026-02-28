from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import re


class RoleEnum(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"


class CreateUserRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: RoleEnum = RoleEnum.EMPLOYEE
    permissions: Optional[List[str]] = None
    designation: Optional[str] = None
    is_active: bool = True

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not cleaned.replace("+", "").isdigit():
            raise ValueError("Invalid phone number format")
        return cleaned


class UpdateUserRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone: Optional[str] = None
    designation: Optional[str] = None
    role: Optional[RoleEnum] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None
