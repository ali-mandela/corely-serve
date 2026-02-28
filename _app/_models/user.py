from datetime import datetime
from typing import List, Optional
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from enum import Enum


class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"  # Organization owner
    ADMIN = "admin"  # Organization admin
    MANAGER = "manager"  # Store manager
    EMPLOYEE = "employee"  # Regular employee


class UserPermission(str, Enum):
    # Organization permissions
    MANAGE_ORGANIZATION = "manage_organization"
    MANAGE_BILLING = "manage_billing"

    # Store permissions
    MANAGE_STORES = "manage_stores"
    CREATE_STORES = "create_stores"
    UPDATE_STORES = "update_stores"
    DELETE_STORES = "delete_stores"

    # Product permissions
    READ_PRODUCTS = "read_products"
    CREATE_PRODUCTS = "create_products"
    UPDATE_PRODUCTS = "update_products"
    DELETE_PRODUCTS = "delete_products"
    MANAGE_CATEGORIES = "manage_categories"

    # Inventory permissions
    READ_INVENTORY = "read_inventory"
    UPDATE_INVENTORY = "update_inventory"
    MANAGE_SUPPLIERS = "manage_suppliers"
    MANAGE_TRANSFERS = "manage_transfers"

    # Sales permissions
    READ_SALES = "read_sales"
    CREATE_SALES = "create_sales"
    UPDATE_SALES = "update_sales"
    DELETE_SALES = "delete_sales"
    PROCESS_RETURNS = "process_returns"

    # Customer permissions
    READ_CUSTOMERS = "read_customers"
    CREATE_CUSTOMERS = "create_customers"
    UPDATE_CUSTOMERS = "update_customers"
    DELETE_CUSTOMERS = "delete_customers"
    MANAGE_LOYALTY = "manage_loyalty"

    # User permissions
    READ_USERS = "read_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    ASSIGN_ROLES = "assign_roles"

    # Financial permissions
    VIEW_FINANCIAL_REPORTS = "view_financial_reports"
    MANAGE_PAYMENTS = "manage_payments"
    EXPORT_DATA = "export_data"

    # System permissions
    MANAGE_SETTINGS = "manage_settings"
    VIEW_AUDIT_LOGS = "view_audit_logs"


ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: ["*"],  # Super admin has all permissions
    UserRole.ADMIN: [
        UserPermission.MANAGE_ORGANIZATION.value,
        UserPermission.MANAGE_BILLING.value,
        UserPermission.MANAGE_STORES.value,
        UserPermission.CREATE_STORES.value,
        UserPermission.UPDATE_STORES.value,
        UserPermission.DELETE_STORES.value,
        UserPermission.READ_PRODUCTS.value,
        UserPermission.CREATE_PRODUCTS.value,
        UserPermission.UPDATE_PRODUCTS.value,
        UserPermission.DELETE_PRODUCTS.value,
        UserPermission.MANAGE_CATEGORIES.value,
        UserPermission.READ_INVENTORY.value,
        UserPermission.UPDATE_INVENTORY.value,
        UserPermission.MANAGE_SUPPLIERS.value,
        UserPermission.READ_SALES.value,
        UserPermission.CREATE_SALES.value,
        UserPermission.UPDATE_SALES.value,
        UserPermission.DELETE_SALES.value,
        UserPermission.READ_CUSTOMERS.value,
        UserPermission.CREATE_CUSTOMERS.value,
        UserPermission.UPDATE_CUSTOMERS.value,
        UserPermission.DELETE_CUSTOMERS.value,
        UserPermission.READ_USERS.value,
        UserPermission.CREATE_USERS.value,
        UserPermission.UPDATE_USERS.value,
        UserPermission.DELETE_USERS.value,
        UserPermission.ASSIGN_ROLES.value,
        UserPermission.VIEW_FINANCIAL_REPORTS.value,
        UserPermission.EXPORT_DATA.value,
        UserPermission.MANAGE_SETTINGS.value,
        UserPermission.VIEW_AUDIT_LOGS.value,
    ],
    UserRole.MANAGER: [
        UserPermission.READ_PRODUCTS.value,
        UserPermission.CREATE_PRODUCTS.value,
        UserPermission.UPDATE_PRODUCTS.value,
        UserPermission.READ_INVENTORY.value,
        UserPermission.UPDATE_INVENTORY.value,
        UserPermission.READ_SALES.value,
        UserPermission.CREATE_SALES.value,
        UserPermission.UPDATE_SALES.value,
        UserPermission.PROCESS_RETURNS.value,
        UserPermission.READ_CUSTOMERS.value,
        UserPermission.CREATE_CUSTOMERS.value,
        UserPermission.UPDATE_CUSTOMERS.value,
        UserPermission.READ_USERS.value,
        UserPermission.CREATE_USERS.value,
        UserPermission.UPDATE_USERS.value,
        UserPermission.VIEW_FINANCIAL_REPORTS.value,
        UserPermission.EXPORT_DATA.value,
        UserPermission.MANAGE_PAYMENTS.value,
    ],
    UserRole.EMPLOYEE: [
        UserPermission.READ_PRODUCTS.value,
        UserPermission.READ_INVENTORY.value,
        UserPermission.READ_SALES.value,
        UserPermission.CREATE_SALES.value,
        UserPermission.UPDATE_SALES.value,
        UserPermission.PROCESS_RETURNS.value,
        UserPermission.READ_CUSTOMERS.value,
        UserPermission.CREATE_CUSTOMERS.value,
        UserPermission.UPDATE_CUSTOMERS.value,
    ],
}


class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        from pydantic_core import core_schema

        return core_schema.with_info_after_validator_function(
            cls.validate,
            core_schema.str_schema(),
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def validate(cls, v, info=None):
        if isinstance(v, ObjectId):
            return v
        if isinstance(v, str) and ObjectId.is_valid(v):
            return ObjectId(v)
        raise ValueError("Invalid ObjectId")

    def __str__(self):
        return str(super())


class User(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password_hash: str
    full_name: Optional[str] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)

    # Multi-tenancy
    organization_id: Optional[PyObjectId] = None  # None for super_admin
    role: UserRole = UserRole.EMPLOYEE

    # Store access
    store_ids: List[PyObjectId] = Field(
        default_factory=list
    )  # Stores user has access to
    default_store_id: Optional[PyObjectId] = None  # Default store for operations

    # Permissions
    permissions: List[str] = Field(default_factory=list)
    custom_permissions: List[str] = Field(
        default_factory=list
    )  # Additional permissions

    # Profile
    avatar_url: Optional[str] = None
    timezone: str = "UTC"
    language: str = "en"

    # Status
    is_active: bool = True
    is_verified: bool = False
    email_verified: bool = False

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "email": "john@example.com",
                "role": "employee",
                "store_ids": [],
                "permissions": ["read_products", "create_sales"],
                "is_active": True,
            }
        }
