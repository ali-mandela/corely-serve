from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

from .common_schema import Address  # Assuming Address is a Pydantic model


class CustomerType(str, Enum):
    RETAIL = "retail"
    WHOLESALE = "wholesale"


class CompanyInfo(BaseModel):
    name: str
    address: Optional[Address] = None
    phone: Optional[str] = None


class AddCustomer(BaseModel):
    # Personal Info
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone: str
    customer_type: CustomerType = CustomerType.RETAIL
    address: Optional[Address] = None
    company: Optional[CompanyInfo] = None
    # organization_id: Optional[str] = None

    # Additional metadata
    other_meta: dict = {}


# from pydantic import BaseModel, EmailStr, Field
# from typing import Optional, List
# from uuid import UUID, uuid4
# from datetime import datetime

# class Customer(BaseModel):
#     id: UUID = Field(default_factory=uuid4)

#     # Personal Info
#     first_name: str
#     last_name: str
#     email: Optional[EmailStr] = None
#     phone: Optional[str] = None

#     # Status
#     is_active: bool = True
#     created_at: datetime = Field(default_factory=datetime.utcnow)
#     updated_at: datetime = Field(default_factory=datetime.utcnow)

#     # Optional ABAC / permissions
#     roles: List[str] = []              # e.g., "regular", "premium"
#     custom_permissions: List[str] = [] # fine-grained access

#     # Optional metadata / tags
#     tags: List[str] = []               # e.g., VIP, newsletter_subscriber

#     class Config:
#         orm_mode = True
