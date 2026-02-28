from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
from bson import ObjectId
from app._models.user import UserRole


class OrganizationInfo(BaseModel):
    """Organization information for user response"""

    id: str
    name: str
    slug: Optional[str] = None
    is_active: bool = True
    plan: Optional[str] = None


class UserCreate(BaseModel):
    """Schema for creating a new user"""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    phone: Optional[str] = None
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    role: UserRole = UserRole.EMPLOYEE
    organization_id: Optional[str] = None
    store_ids: List[str] = []
    default_store_id: Optional[str] = None
    permissions: List[str] = []
    custom_permissions: List[str] = []
    timezone: str = "UTC"
    language: str = "en"


class UserCreateFromInvitation(BaseModel):
    """Schema for creating user from invitation"""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None


class UserUpdate(BaseModel):
    """Schema for updating user information"""

    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    organization_id: Optional[str] = None
    store_ids: Optional[List[str]] = None
    default_store_id: Optional[str] = None
    permissions: Optional[List[str]] = None
    custom_permissions: Optional[List[str]] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    """Schema for password change"""

    current_password: str
    new_password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    """Schema for user response"""

    id: str = Field(..., alias="_id")
    username: str
    email: EmailStr
    phone: Optional[str] = None
    full_name: Optional[str] = None
    role: UserRole
    organization_id: str
    store_ids: List[str]
    default_store_id: Optional[str] = None
    permissions: List[str]
    custom_permissions: List[str] = []
    avatar_url: Optional[str] = None
    timezone: str = "UTC"
    language: str = "en"
    is_active: bool
    is_verified: bool = False
    email_verified: bool = False
    created_at: str
    updated_at: Optional[str] = None
    last_login: Optional[str] = None
    organization: OrganizationInfo

    @field_validator("id", mode="before")
    @classmethod
    def validate_object_id(cls, v):
        """Convert ObjectId to string if needed"""
        if isinstance(v, ObjectId):
            return str(v)
        return v

    @field_validator("organization_id", mode="before")
    @classmethod
    def validate_organization_id(cls, v):
        """Convert ObjectId to string if needed"""
        if isinstance(v, ObjectId):
            return str(v)
        return v

    @field_validator("store_ids", mode="before")
    @classmethod
    def validate_store_ids(cls, v):
        """Convert ObjectIds to strings if needed"""
        if isinstance(v, list):
            return [str(item) if isinstance(item, ObjectId) else item for item in v]
        return v

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}


class UserLogin(BaseModel):
    """Schema for user login"""

    identifier: str = Field(..., description="Username, email, or phone number")
    password: str


class Token(BaseModel):
    """Schema for authentication token response"""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class UserListResponse(BaseModel):
    """Schema for paginated user list response"""

    users: List[UserResponse]
    total: int
    page: int
    per_page: int
    pages: int


class InviteUser(BaseModel):
    """Schema for inviting a user"""

    email: EmailStr
    role: UserRole
    organization_id: str
    store_ids: List[str] = []
    permissions: List[str] = []


class UserInvitation(BaseModel):
    """Schema for user invitation"""

    id: str
    email: EmailStr
    role: UserRole
    organization_id: str
    store_ids: List[str]
    permissions: List[str]
    invited_by: str
    expires_at: str
    is_used: bool = False
    created_at: str
