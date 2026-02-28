"""
Audit Log schemas — tracks every important action across all modules.
"""

from pydantic import BaseModel, Field
from typing import Optional, Any
from enum import Enum


class AuditActionEnum(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    REJECT = "reject"
    OTHER = "other"


class AuditModuleEnum(str, Enum):
    USERS = "users"
    CUSTOMERS = "customers"
    VENDORS = "vendors"
    ITEMS = "items"
    INVENTORY = "inventory"
    POS = "pos"
    INVOICES = "invoices"
    AUTH = "auth"
    ORGANIZATION = "organization"
    SETTINGS = "settings"
    OTHER = "other"


class AuditLogEntry(BaseModel):
    """
    Schema for reading/displaying audit logs.
    Not a request schema — logs are created internally by the AuditService.
    """
    module: AuditModuleEnum
    action: AuditActionEnum
    resource_id: Optional[str] = Field(None, description="ID of the affected document")
    description: str = Field(..., min_length=1, max_length=500)

    # Change tracking
    before: Optional[Any] = Field(None, description="Document state before the change")
    after: Optional[Any] = Field(None, description="Document state after the change")
    changed_fields: Optional[list[str]] = Field(None, description="List of fields that changed")

    # Context
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    ip_address: Optional[str] = None
