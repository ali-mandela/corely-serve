from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

from app._models.user import UserRole


class UserInvitation(BaseModel):
    email: EmailStr
    role: UserRole
    store_ids: List[str] = []
    permissions: List[str] = []
    message: Optional[str] = None


class InvitationResponse(BaseModel):
    id: str
    email: str
    role: str
    store_ids: List[str]
    permissions: List[str]
    invited_by: str
    created_at: str
    expires_at: str
    used: bool
    token: str


class AcceptInvitationRequest(BaseModel):
    token: str
    username: str
    password: str
    full_name: Optional[str] = None


class InvitationVerificationResponse(BaseModel):
    email: str
    role: str
    store_ids: List[str]
    permissions: List[str]
    invited_by: str
    expires_at: str
    valid: bool = True