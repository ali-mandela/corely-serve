from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from app._schemas.organization_schema import Address


class OnboardingRequest(BaseModel):
    # Super Admin details
    admin_username: str = Field(..., min_length=3, max_length=50)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=6)
    admin_full_name: str = Field(..., min_length=1, max_length=100)
    admin_phone: Optional[str] = Field(None, min_length=10, max_length=15)

    # Organization details
    org_name: str = Field(..., min_length=1, max_length=100)
    org_slug: str = Field(..., min_length=1, max_length=50)
    org_description: Optional[str] = None
    org_email: EmailStr
    org_phone: Optional[str] = Field(None, min_length=10, max_length=15)
    org_website: Optional[str] = None
    org_address: Address
    allowed_modules: list = Field(default_factory=list)


class OnboardingResponse(BaseModel):
    message: str
    admin_user_id: str
    organization_id: str
    access_token: str
