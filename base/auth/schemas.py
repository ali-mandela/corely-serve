from pydantic import BaseModel, EmailStr
from typing import Optional


class LoginRequest(BaseModel):
    """POST /auth/login"""
    identifier: str        # email or phone
    password: str
    slug: str              # organization slug


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
