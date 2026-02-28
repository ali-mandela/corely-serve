"""
Permissions and access control dependencies
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import Depends, HTTPException, status

from .auth import get_current_active_user
from ..access_control import get_access_control_manager, AccessControlManager

logger = logging.getLogger(__name__)


class PermissionChecker:
    """
    Base class for permission checking
    """
    def __init__(self, resource_type: str, action: str):
        self.resource_type = resource_type
        self.action = action

    async def __call__(
        self,
        current_user: Dict[str, Any] = Depends(get_current_active_user),
        ac_manager: AccessControlManager = Depends(get_access_control_manager)
    ) -> Dict[str, Any]:
        # Check permission
        has_permission = await ac_manager.check_permission(
            user_id=current_user["id"],
            resource_type=self.resource_type,
            action=self.action,
            tenant_id=current_user.get("tenant_id")
        )

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {self.action} on {self.resource_type}"
            )

        return current_user


class ResourcePermissionChecker:
    """
    Check permissions for specific resource instances
    """
    def __init__(self, resource_type: str, action: str, resource_param: str = "resource_id"):
        self.resource_type = resource_type
        self.action = action
        self.resource_param = resource_param

    async def __call__(
        self,
        resource_id: str,
        current_user: Dict[str, Any] = Depends(get_current_active_user),
        ac_manager: AccessControlManager = Depends(get_access_control_manager)
    ) -> Dict[str, Any]:
        # Check permission for specific resource
        has_permission = await ac_manager.check_resource_permission(
            user_id=current_user["id"],
            resource_type=self.resource_type,
            resource_id=resource_id,
            action=self.action,
            tenant_id=current_user.get("tenant_id")
        )

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {self.action} on {self.resource_type}:{resource_id}"
            )

        return current_user


# Common permission checkers

# User management permissions
can_read_users = PermissionChecker("users", "read")
can_create_users = PermissionChecker("users", "create")
can_update_users = PermissionChecker("users", "update")
can_delete_users = PermissionChecker("users", "delete")

# Store management permissions
can_read_stores = PermissionChecker("stores", "read")
can_create_stores = PermissionChecker("stores", "create")
can_update_stores = PermissionChecker("stores", "update")
can_delete_stores = PermissionChecker("stores", "delete")
can_manage_stores = PermissionChecker("stores", "manage")

# Product management permissions
can_read_products = PermissionChecker("products", "read")
can_create_products = PermissionChecker("products", "create")
can_update_products = PermissionChecker("products", "update")
can_delete_products = PermissionChecker("products", "delete")
can_manage_inventory = PermissionChecker("inventory", "manage")

# Employee management permissions
can_read_employees = PermissionChecker("employees", "read")
can_create_employees = PermissionChecker("employees", "create")
can_update_employees = PermissionChecker("employees", "update")
can_delete_employees = PermissionChecker("employees", "delete")
can_manage_schedules = PermissionChecker("schedules", "manage")

# Transaction permissions
can_read_transactions = PermissionChecker("transactions", "read")
can_create_transactions = PermissionChecker("transactions", "create")
can_refund_transactions = PermissionChecker("transactions", "refund")
can_void_transactions = PermissionChecker("transactions", "void")

# Reporting permissions
can_view_reports = PermissionChecker("reports", "read")
can_export_reports = PermissionChecker("reports", "export")
can_view_analytics = PermissionChecker("analytics", "read")

# Admin permissions
can_manage_settings = PermissionChecker("settings", "manage")
can_manage_integrations = PermissionChecker("integrations", "manage")
can_view_audit_logs = PermissionChecker("audit_logs", "read")
can_manage_roles = PermissionChecker("roles", "manage")
can_manage_permissions = PermissionChecker("permissions", "manage")

# Tenant admin permissions
can_manage_tenant = PermissionChecker("tenant", "manage")
can_view_tenant_analytics = PermissionChecker("tenant_analytics", "read")
can_manage_billing = PermissionChecker("billing", "manage")

# System admin permissions
can_manage_system = PermissionChecker("system", "manage")
can_view_system_health = PermissionChecker("system_health", "read")
can_manage_maintenance = PermissionChecker("maintenance", "manage")


# Resource-specific permission checkers
class StoreAccessChecker:
    """Check access to specific store"""
    async def __call__(
        self,
        store_id: str,
        current_user: Dict[str, Any] = Depends(get_current_active_user),
        ac_manager: AccessControlManager = Depends(get_access_control_manager)
    ) -> Dict[str, Any]:
        # Check if user has access to this store
        has_access = await ac_manager.check_store_access(
            user_id=current_user["id"],
            store_id=store_id,
            tenant_id=current_user.get("tenant_id")
        )

        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to store: {store_id}"
            )

        return current_user


class TenantAccessChecker:
    """Check access to tenant resources"""
    async def __call__(
        self,
        tenant_id: str,
        current_user: Dict[str, Any] = Depends(get_current_active_user)
    ) -> Dict[str, Any]:
        user_tenant_id = current_user.get("tenant_id")

        # Users can only access their own tenant's resources
        if user_tenant_id != tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: cannot access other tenant's resources"
            )

        return current_user


# Convenience instances
store_access_required = StoreAccessChecker()
tenant_access_required = TenantAccessChecker()


def require_any_permission(*permissions: str):
    """
    Require any of the specified permissions
    """
    async def check_any_permission(
        current_user: Dict[str, Any] = Depends(get_current_active_user),
        ac_manager: AccessControlManager = Depends(get_access_control_manager)
    ) -> Dict[str, Any]:
        user_permissions = current_user.get("permissions", [])

        if not any(perm in user_permissions for perm in permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(permissions)}"
            )

        return current_user

    return check_any_permission


def require_all_permissions(*permissions: str):
    """
    Require all of the specified permissions
    """
    async def check_all_permissions(
        current_user: Dict[str, Any] = Depends(get_current_active_user),
        ac_manager: AccessControlManager = Depends(get_access_control_manager)
    ) -> Dict[str, Any]:
        user_permissions = current_user.get("permissions", [])
        missing_permissions = [p for p in permissions if p not in user_permissions]

        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: {', '.join(missing_permissions)}"
            )

        return current_user

    return check_all_permissions


class ConditionalPermission:
    """
    Apply permission based on condition
    """
    def __init__(self, condition_func, permission_checker):
        self.condition_func = condition_func
        self.permission_checker = permission_checker

    async def __call__(
        self,
        current_user: Dict[str, Any] = Depends(get_current_active_user)
    ) -> Dict[str, Any]:
        if await self.condition_func(current_user):
            return await self.permission_checker(current_user)
        return current_user


# Business hours permission check
class BusinessHoursChecker:
    """Check if current time is within business hours"""
    def __init__(self, require_business_hours: bool = True):
        self.require_business_hours = require_business_hours

    async def __call__(
        self,
        current_user: Dict[str, Any] = Depends(get_current_active_user)
    ) -> Dict[str, Any]:
        from datetime import datetime, time

        current_time = datetime.now().time()
        business_start = time(9, 0)  # 9 AM
        business_end = time(18, 0)   # 6 PM

        is_business_hours = business_start <= current_time <= business_end

        if self.require_business_hours and not is_business_hours:
            # Check if user has after-hours permission
            if "after_hours_access" not in current_user.get("permissions", []):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Operation not allowed outside business hours"
                )

        return current_user


# Common instances
business_hours_required = BusinessHoursChecker(True)
business_hours_optional = BusinessHoursChecker(False)