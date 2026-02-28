"""
Profile schemas — user self-service for profile and password management.
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional
import re


class UpdateProfileRequest(BaseModel):
    """PUT /profile/me — Update own profile info."""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone: Optional[str] = Field(None, max_length=15)
    avatar_url: Optional[str] = Field(None, max_length=500)

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        if v:
            cleaned = re.sub(r"[\s\-\(\)]", "", v)
            if not cleaned.replace("+", "").isdigit():
                raise ValueError("Invalid phone number")
            return cleaned
        return v


class ChangePasswordRequest(BaseModel):
    """POST /profile/change-password"""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v):
        """Ensure password has at least 1 uppercase, 1 lowercase, 1 digit."""
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v
