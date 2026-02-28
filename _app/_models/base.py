from pydantic import BaseModel, Field
from typing import Optional
from bson import ObjectId


class AdminInfo(BaseModel):
    site_code: str
    admin_email: str
    admin_password: str
    admin_full_name: str
    admin_phone: str
    admin_role: str = "APP_ADMIN"
    is_active: bool = True


class AdminResponse(AdminInfo):
    id: Optional[str] = Field(None, alias="_id")
    created_at: str
    updated_at: str


class AdminLogin(BaseModel):
    site_code: str
    email: str
    password: str
