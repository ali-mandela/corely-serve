"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Permissions Management Module

This module provides comprehensive permission management that integrates with roles,
modules, and organizational structure to provide fine-grained access control.

Features:
- Dynamic permission calculation based on role and context
- Module-specific permission sets
- Store and warehouse scoped permissions
- Permission inheritance and overrides
- High-performance permission caching
- Real-time permission evaluation
- Permission templates and bulk assignment
- Audit trail for permission changes
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from functools import lru_cache
import hashlib

from app._core.config.settings import get_settings
from app._core.database.connection import get_connection_manager
from app._core.auth.tokens import ROLE_HIERARCHY
from app._core.auth.sessions import ORGANIZATION_MODULES
from app._core.utils.exceptions import ValidationException, AuthorizationException
from app._core.utils.constants import DatabaseConstants


logger = logging.getLogger(__name__)


class PermissionScope(Enum):
    """Permission scopes for different levels of access."""

    GLOBAL = "global"  # System-wide permissions
    TENANT = "tenant"  # Tenant-wide permissions
    STORE = "store"  # Store-specific permissions
    WAREHOUSE = "warehouse"  # Warehouse-specific permissions
    DEPARTMENT = "department"  # Department-specific permissions
    USER = "user"  # User-specific permissions


class PermissionType(Enum):
    """Types of permissions in Corely system."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    OVERRIDE = "override"
    ADMIN = "admin"


# Comprehensive permission definitions for Corely retail system
CORELY_PERMISSIONS = {
    # User Management
    "users.read": "View user information",
    "users.write": "Create and edit users",
    "users.delete": "Delete users",
    "users.admin": "Full user management access",
    "users.roles.assign": "Assign roles to users",
    "users.permissions.manage": "Manage user permissions",
    "users.sessions.manage": "Manage user sessions",
    # Store Management
    "stores.read": "View store information",
    "stores.write": "Create and edit stores",
    "stores.delete": "Delete stores",
    "stores.admin": "Full store management access",
    "stores.settings.manage": "Manage store settings",
    "stores.hours.manage": "Manage store hours",
    "stores.staff.manage": "Manage store staff",
    # Inventory Module
    "inventory.products.read": "View product inventory",
    "inventory.products.write": "Create and edit products",
    "inventory.products.delete": "Delete products",
    "inventory.stock.read": "View stock levels",
    "inventory.stock.write": "Adjust stock levels",
    "inventory.stock.transfer": "Transfer stock between locations",
    "inventory.adjustments.approve": "Approve inventory adjustments",
    "inventory.reports.read": "View inventory reports",
    "inventory.categories.manage": "Manage product categories",
    "inventory.suppliers.manage": "Manage suppliers",
    "inventory.pricing.manage": "Manage product pricing",
    "inventory.barcode.generate": "Generate product barcodes",
    # Warehouse Module
    "warehouse.locations.read": "View warehouse locations",
    "warehouse.locations.write": "Create and edit warehouse locations",
    "warehouse.receiving.execute": "Process incoming shipments",
    "warehouse.picking.execute": "Process picking orders",
    "warehouse.shipping.execute": "Process outbound shipments",
    "warehouse.cycle_count.execute": "Perform cycle counts",
    "warehouse.reports.read": "View warehouse reports",
    "warehouse.staff.manage": "Manage warehouse staff",
    "warehouse.equipment.manage": "Manage warehouse equipment",
    # Point of Sale Module
    "pos.sales.execute": "Process sales transactions",
    "pos.returns.execute": "Process returns",
    "pos.exchanges.execute": "Process exchanges",
    "pos.discounts.apply": "Apply discounts",
    "pos.voids.execute": "Void transactions",
    "pos.cash_management.execute": "Manage cash drawer",
    "pos.reports.read": "View POS reports",
    "pos.settings.manage": "Manage POS settings",
    "pos.receipts.reprint": "Reprint receipts",
    "pos.offline.execute": "Process offline transactions",
    # Customer Management
    "customers.read": "View customer information",
    "customers.write": "Create and edit customers",
    "customers.delete": "Delete customers",
    "customers.history.read": "View customer purchase history",
    "customers.loyalty.manage": "Manage customer loyalty points",
    "customers.communication.send": "Send customer communications",
    "customers.privacy.access": "Access customer private data",
    # Analytics Module
    "analytics.sales.read": "View sales analytics",
    "analytics.inventory.read": "View inventory analytics",
    "analytics.customer.read": "View customer analytics",
    "analytics.financial.read": "View financial analytics",
    "analytics.operations.read": "View operational analytics",
    "analytics.forecasting.read": "View forecasting data",
    "analytics.dashboards.read": "View analytics dashboards",
    "analytics.reports.export": "Export analytics reports",
    "analytics.custom.create": "Create custom analytics",
    # Accounting Module
    "accounting.transactions.read": "View financial transactions",
    "accounting.transactions.write": "Create financial transactions",
    "accounting.reconciliation.execute": "Perform account reconciliation",
    "accounting.reports.read": "View financial reports",
    "accounting.tax.manage": "Manage tax calculations",
    "accounting.payroll.read": "View payroll information",
    "accounting.budgets.manage": "Manage budgets",
    "accounting.audit.access": "Access audit information",
    # Human Resources Module
    "hr.employees.read": "View employee information",
    "hr.employees.write": "Create and edit employees",
    "hr.employees.delete": "Delete employees",
    "hr.schedules.manage": "Manage employee schedules",
    "hr.payroll.manage": "Manage payroll",
    "hr.benefits.manage": "Manage employee benefits",
    "hr.performance.manage": "Manage performance reviews",
    "hr.training.manage": "Manage training programs",
    "hr.compliance.manage": "Manage HR compliance",
    # Supply Chain Module
    "supply_chain.vendors.read": "View vendor information",
    "supply_chain.vendors.write": "Create and edit vendors",
    "supply_chain.purchase_orders.read": "View purchase orders",
    "supply_chain.purchase_orders.write": "Create purchase orders",
    "supply_chain.purchase_orders.approve": "Approve purchase orders",
    "supply_chain.contracts.manage": "Manage vendor contracts",
    "supply_chain.logistics.manage": "Manage logistics",
    "supply_chain.quality.manage": "Manage quality control",
    # Loyalty Module
    "loyalty.programs.read": "View loyalty programs",
    "loyalty.programs.write": "Create and edit loyalty programs",
    "loyalty.points.manage": "Manage customer points",
    "loyalty.rewards.manage": "Manage rewards catalog",
    "loyalty.campaigns.manage": "Manage loyalty campaigns",
    "loyalty.analytics.read": "View loyalty analytics",
    # Reporting Module
    "reports.standard.read": "View standard reports",
    "reports.custom.create": "Create custom reports",
    "reports.custom.share": "Share custom reports",
    "reports.schedule.manage": "Manage scheduled reports",
    "reports.export.execute": "Export reports",
    "reports.admin.manage": "Manage reporting system",
    # Audit Module
    "audit.logs.read": "View audit logs",
    "audit.compliance.read": "View compliance reports",
    "audit.security.read": "View security audit data",
    "audit.data_access.read": "View data access logs",
    "audit.configuration.manage": "Manage audit configuration",
    # Maintenance Module
    "maintenance.equipment.read": "View equipment information",
    "maintenance.equipment.write": "Create and edit equipment",
    "maintenance.schedules.manage": "Manage maintenance schedules",
    "maintenance.work_orders.manage": "Manage work orders",
    "maintenance.reports.read": "View maintenance reports",
    # Security Module
    "security.access.manage": "Manage access controls",
    "security.cameras.read": "View security cameras",
    "security.incidents.manage": "Manage security incidents",
    "security.alerts.manage": "Manage security alerts",
    "security.reports.read": "View security reports",
    # System Administration
    "system.settings.read": "View system settings",
    "system.settings.write": "Modify system settings",
    "system.backups.manage": "Manage system backups",
    "system.integrations.manage": "Manage system integrations",
    "system.logs.read": "View system logs",
    "system.monitoring.read": "View system monitoring",
    "system.maintenance.execute": "Execute system maintenance",
}


# Role-based permission templates
ROLE_PERMISSION_TEMPLATES = {
    "SUPER_ADMIN": [
        # Full system access
        "*"  # Wildcard for all permissions
    ],
    "TENANT_ADMIN": [
        # User management
        "users.*",
        # Store management
        "stores.*",
        # All modules except system administration
        "inventory.*",
        "warehouse.*",
        "pos.*",
        "customers.*",
        "analytics.*",
        "accounting.*",
        "hr.*",
        "supply_chain.*",
        "loyalty.*",
        "reports.*",
        "audit.logs.read",
        "audit.compliance.read",
        "maintenance.*",
        "security.*",
    ],
    "TENANT_MANAGER": [
        "users.read",
        "stores.read",
        "stores.settings.manage",
        "inventory.*",
        "warehouse.reports.read",
        "pos.*",
        "customers.*",
        "analytics.*",
        "accounting.reports.read",
        "hr.employees.read",
        "hr.schedules.manage",
        "supply_chain.vendors.read",
        "supply_chain.purchase_orders.*",
        "loyalty.*",
        "reports.standard.read",
        "reports.custom.create",
        "maintenance.reports.read",
    ],
    "STORE_MANAGER": [
        "users.read",
        "stores.read",
        "stores.hours.manage",
        "stores.staff.manage",
        "inventory.products.read",
        "inventory.stock.read",
        "inventory.stock.write",
        "inventory.adjustments.approve",
        "inventory.reports.read",
        "pos.*",
        "customers.*",
        "analytics.sales.read",
        "analytics.customer.read",
        "hr.employees.read",
        "hr.schedules.manage",
        "reports.standard.read",
        "maintenance.equipment.read",
        "maintenance.work_orders.manage",
    ],
    "WAREHOUSE_MANAGER": [
        "users.read",
        "warehouse.*",
        "inventory.products.read",
        "inventory.stock.*",
        "inventory.adjustments.approve",
        "inventory.reports.read",
        "supply_chain.vendors.read",
        "supply_chain.purchase_orders.read",
        "analytics.inventory.read",
        "analytics.operations.read",
        "hr.employees.read",
        "hr.schedules.manage",
        "reports.standard.read",
        "maintenance.*",
    ],
    "ASSISTANT_MANAGER": [
        "users.read",
        "stores.read",
        "inventory.products.read",
        "inventory.stock.read",
        "inventory.stock.write",
        "inventory.reports.read",
        "pos.*",
        "customers.read",
        "customers.write",
        "customers.history.read",
        "analytics.sales.read",
        "hr.employees.read",
        "reports.standard.read",
    ],
    "SHIFT_SUPERVISOR": [
        "users.read",
        "inventory.products.read",
        "inventory.stock.read",
        "pos.*",
        "customers.read",
        "customers.write",
        "customers.history.read",
        "reports.standard.read",
    ],
    "WAREHOUSE_SUPERVISOR": [
        "warehouse.receiving.execute",
        "warehouse.picking.execute",
        "warehouse.shipping.execute",
        "warehouse.cycle_count.execute",
        "warehouse.reports.read",
        "inventory.products.read",
        "inventory.stock.read",
        "inventory.stock.write",
        "reports.standard.read",
    ],
    "CUSTOMER_SERVICE_MANAGER": [
        "customers.*",
        "pos.sales.execute",
        "pos.returns.execute",
        "pos.exchanges.execute",
        "loyalty.*",
        "analytics.customer.read",
        "reports.standard.read",
    ],
    "BUSINESS_ANALYST": [
        "analytics.*",
        "reports.*",
        "inventory.reports.read",
        "warehouse.reports.read",
        "accounting.reports.read",
        "customers.read",
        "customers.history.read",
        "loyalty.analytics.read",
    ],
    "FINANCIAL_ANALYST": [
        "analytics.financial.read",
        "analytics.forecasting.read",
        "accounting.*",
        "reports.standard.read",
        "reports.custom.create",
        "inventory.reports.read",
    ],
    "CASHIER": [
        "pos.sales.execute",
        "pos.returns.execute",
        "pos.exchanges.execute",
        "pos.cash_management.execute",
        "customers.read",
        "customers.write",
        "loyalty.points.manage",
    ],
    "SALES_ASSOCIATE": [
        "pos.sales.execute",
        "pos.returns.execute",
        "pos.exchanges.execute",
        "customers.read",
        "customers.write",
        "inventory.products.read",
        "inventory.stock.read",
        "loyalty.points.manage",
    ],
    "INVENTORY_CLERK": [
        "inventory.products.read",
        "inventory.stock.read",
        "inventory.stock.write",
        "inventory.categories.manage",
        "warehouse.receiving.execute",
        "warehouse.cycle_count.execute",
    ],
    "WAREHOUSE_OPERATOR": [
        "warehouse.receiving.execute",
        "warehouse.picking.execute",
        "warehouse.shipping.execute",
        "inventory.products.read",
        "inventory.stock.read",
    ],
    "CUSTOMER_SERVICE_REP": [
        "customers.read",
        "customers.write",
        "customers.history.read",
        "customers.communication.send",
        "pos.returns.execute",
        "pos.exchanges.execute",
        "loyalty.points.manage",
    ],
    "CUSTOMER": [
        "customers.read",  # Only their own data
        "loyalty.programs.read",
    ],
}


@dataclass
class Permission:
    """Individual permission definition."""

    name: str
    description: str
    module: str
    scope: PermissionScope = PermissionScope.TENANT
    permission_type: PermissionType = PermissionType.READ

    def matches_pattern(self, pattern: str) -> bool:
        """Check if permission matches a pattern (supports wildcards)."""
        if pattern == "*":
            return True

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return self.name.startswith(prefix)

        return self.name == pattern


@dataclass
class PermissionSet:
    """Set of permissions for a user/role."""

    user_id: str
    role: str
    tenant_id: Optional[str]
    store_id: Optional[str]
    warehouse_id: Optional[str]
    permissions: List[str]
    effective_permissions: List[str] = field(default_factory=list)
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    def has_permission(self, permission: str) -> bool:
        """Check if permission set includes a specific permission."""
        return permission in self.effective_permissions

    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if permission set includes any of the specified permissions."""
        return any(perm in self.effective_permissions for perm in permissions)

    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if permission set includes all specified permissions."""
        return all(perm in self.effective_permissions for perm in permissions)


class PermissionManager:
    """Comprehensive permission management system for Corely."""

    def __init__(self):
        self.settings = get_settings()
        self.cache_ttl = timedelta(minutes=15)  # Cache permissions for 15 minutes
        self._permission_cache: Dict[str, PermissionSet] = {}
        self._cache_lock = asyncio.Lock()

    async def get_user_permissions(
        self,
        user_id: str,
        role: str,
        tenant_id: Optional[str] = None,
        store_id: Optional[str] = None,
        warehouse_id: Optional[str] = None,
        use_cache: bool = True,
    ) -> PermissionSet:
        """Get comprehensive permission set for a user."""

        # Create cache key
        cache_key = self._create_cache_key(
            user_id, role, tenant_id, store_id, warehouse_id
        )

        # Check cache first
        if use_cache:
            cached_permissions = await self._get_cached_permissions(cache_key)
            if cached_permissions:
                return cached_permissions

        try:
            # Calculate permissions
            permission_set = await self._calculate_user_permissions(
                user_id, role, tenant_id, store_id, warehouse_id
            )

            # Cache the result
            if use_cache:
                await self._cache_permissions(cache_key, permission_set)

            return permission_set

        except Exception as e:
            logger.error(f"Failed to get user permissions: {str(e)}")
            # Return minimal permissions on error
            return PermissionSet(
                user_id=user_id,
                role=role,
                tenant_id=tenant_id,
                store_id=store_id,
                warehouse_id=warehouse_id,
                permissions=[],
                effective_permissions=[],
            )

    async def _calculate_user_permissions(
        self,
        user_id: str,
        role: str,
        tenant_id: Optional[str],
        store_id: Optional[str],
        warehouse_id: Optional[str],
    ) -> PermissionSet:
        """Calculate effective permissions for a user."""

        # Start with role-based permissions
        role_permissions = self._get_role_permissions(role)

        # Get user-specific permission overrides
        user_permissions = await self._get_user_specific_permissions(user_id)

        # Get tenant-specific permission restrictions
        tenant_restrictions = await self._get_tenant_restrictions(tenant_id)

        # Get store/warehouse specific permissions
        location_permissions = await self._get_location_permissions(
            tenant_id, store_id, warehouse_id
        )

        # Combine all permissions
        all_permissions = set()
        all_permissions.update(role_permissions)
        all_permissions.update(user_permissions)
        all_permissions.update(location_permissions)

        # Apply tenant restrictions
        if tenant_restrictions:
            all_permissions = all_permissions.intersection(set(tenant_restrictions))

        # Resolve permission patterns to actual permissions
        effective_permissions = self._resolve_permission_patterns(list(all_permissions))

        # Filter by enabled modules for tenant
        enabled_modules = await self._get_tenant_enabled_modules(tenant_id)
        filtered_permissions = self._filter_permissions_by_modules(
            effective_permissions, enabled_modules
        )

        return PermissionSet(
            user_id=user_id,
            role=role,
            tenant_id=tenant_id,
            store_id=store_id,
            warehouse_id=warehouse_id,
            permissions=list(all_permissions),
            effective_permissions=filtered_permissions,
            expires_at=datetime.now(timezone.utc) + self.cache_ttl,
        )

    def _get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a specific role."""
        return ROLE_PERMISSION_TEMPLATES.get(role, [])

    async def _get_user_specific_permissions(self, user_id: str) -> List[str]:
        """Get user-specific permission overrides."""
        try:
            manager = await get_connection_manager()

            async with manager.get_collection("user_permissions") as collection:
                user_perms = await collection.find_one({"user_id": user_id})

                if user_perms:
                    granted = user_perms.get("granted_permissions", [])
                    revoked = user_perms.get("revoked_permissions", [])

                    # Return granted permissions (revoked will be handled separately)
                    return granted

                return []

        except Exception as e:
            logger.error(f"Failed to get user permissions: {str(e)}")
            return []

    async def _get_tenant_restrictions(
        self, tenant_id: Optional[str]
    ) -> Optional[List[str]]:
        """Get tenant-level permission restrictions."""
        if not tenant_id:
            return None

        try:
            manager = await get_connection_manager()

            async with manager.get_collection(DatabaseConstants.TENANTS) as collection:
                tenant = await collection.find_one({"_id": tenant_id})

                if tenant:
                    return tenant.get("allowed_permissions")

                return None

        except Exception as e:
            logger.error(f"Failed to get tenant restrictions: {str(e)}")
            return None

    async def _get_location_permissions(
        self,
        tenant_id: Optional[str],
        store_id: Optional[str],
        warehouse_id: Optional[str],
    ) -> List[str]:
        """Get location-specific permissions."""
        permissions = []

        try:
            manager = await get_connection_manager()

            # Store-specific permissions
            if store_id:
                async with manager.get_collection("stores") as collection:
                    store = await collection.find_one(
                        {"_id": store_id, "tenant_id": tenant_id}
                    )
                    if store:
                        permissions.extend(store.get("additional_permissions", []))

            # Warehouse-specific permissions
            if warehouse_id:
                async with manager.get_collection("warehouses") as collection:
                    warehouse = await collection.find_one(
                        {"_id": warehouse_id, "tenant_id": tenant_id}
                    )
                    if warehouse:
                        permissions.extend(warehouse.get("additional_permissions", []))

            return permissions

        except Exception as e:
            logger.error(f"Failed to get location permissions: {str(e)}")
            return []

    async def _get_tenant_enabled_modules(self, tenant_id: Optional[str]) -> Set[str]:
        """Get enabled modules for tenant."""
        if not tenant_id:
            return set(ORGANIZATION_MODULES.keys())

        try:
            manager = await get_connection_manager()

            async with manager.get_collection(DatabaseConstants.TENANTS) as collection:
                tenant = await collection.find_one({"_id": tenant_id})

                if tenant:
                    return set(
                        tenant.get("enabled_modules", list(ORGANIZATION_MODULES.keys()))
                    )

                return set(ORGANIZATION_MODULES.keys())

        except Exception as e:
            logger.error(f"Failed to get enabled modules: {str(e)}")
            return set(["inventory", "pos"])  # Default modules

    def _resolve_permission_patterns(self, permission_patterns: List[str]) -> List[str]:
        """Resolve permission patterns (wildcards) to actual permissions."""
        resolved_permissions = set()

        for pattern in permission_patterns:
            if pattern == "*":
                # Grant all permissions
                resolved_permissions.update(CORELY_PERMISSIONS.keys())
            elif pattern.endswith("*"):
                # Wildcard pattern
                prefix = pattern[:-1]
                matching_permissions = [
                    perm
                    for perm in CORELY_PERMISSIONS.keys()
                    if perm.startswith(prefix)
                ]
                resolved_permissions.update(matching_permissions)
            else:
                # Exact permission
                if pattern in CORELY_PERMISSIONS:
                    resolved_permissions.add(pattern)

        return list(resolved_permissions)

    def _filter_permissions_by_modules(
        self, permissions: List[str], enabled_modules: Set[str]
    ) -> List[str]:
        """Filter permissions based on enabled modules."""
        filtered_permissions = []

        for permission in permissions:
            # Extract module from permission name
            module = permission.split(".")[0]

            # System permissions are always allowed
            if module in ["system", "users", "stores"]:
                filtered_permissions.append(permission)
            # Module-specific permissions only if module is enabled
            elif module in enabled_modules:
                filtered_permissions.append(permission)

        return filtered_permissions

    def _create_cache_key(
        self,
        user_id: str,
        role: str,
        tenant_id: Optional[str],
        store_id: Optional[str],
        warehouse_id: Optional[str],
    ) -> str:
        """Create cache key for permission set."""
        key_parts = [user_id, role]
        if tenant_id:
            key_parts.append(tenant_id)
        if store_id:
            key_parts.append(f"store:{store_id}")
        if warehouse_id:
            key_parts.append(f"warehouse:{warehouse_id}")

        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()

    async def _get_cached_permissions(self, cache_key: str) -> Optional[PermissionSet]:
        """Get permissions from cache if not expired."""
        async with self._cache_lock:
            cached = self._permission_cache.get(cache_key)

            if cached and cached.expires_at:
                if datetime.now(timezone.utc) < cached.expires_at:
                    return cached
                else:
                    # Remove expired cache entry
                    del self._permission_cache[cache_key]

            return None

    async def _cache_permissions(
        self, cache_key: str, permission_set: PermissionSet
    ) -> None:
        """Cache permission set."""
        async with self._cache_lock:
            self._permission_cache[cache_key] = permission_set

            # Clean up expired entries periodically
            if len(self._permission_cache) > 1000:  # Arbitrary limit
                await self._cleanup_cache()

    async def _cleanup_cache(self) -> None:
        """Clean up expired cache entries."""
        now = datetime.now(timezone.utc)
        expired_keys = [
            key
            for key, perm_set in self._permission_cache.items()
            if perm_set.expires_at and now > perm_set.expires_at
        ]

        for key in expired_keys:
            del self._permission_cache[key]

        logger.debug(f"Cleaned up {len(expired_keys)} expired permission cache entries")

    async def invalidate_user_cache(self, user_id: str) -> None:
        """Invalidate all cached permissions for a user."""
        async with self._cache_lock:
            keys_to_remove = [
                key for key in self._permission_cache.keys() if user_id in key
            ]

            for key in keys_to_remove:
                del self._permission_cache[key]

            logger.debug(
                f"Invalidated {len(keys_to_remove)} cache entries for user {user_id}"
            )

    async def check_permission(
        self,
        user_id: str,
        permission: str,
        role: str,
        tenant_id: Optional[str] = None,
        store_id: Optional[str] = None,
        warehouse_id: Optional[str] = None,
    ) -> bool:
        """Check if user has a specific permission."""
        try:
            permission_set = await self.get_user_permissions(
                user_id, role, tenant_id, store_id, warehouse_id
            )

            return permission_set.has_permission(permission)

        except Exception as e:
            logger.error(f"Permission check failed: {str(e)}")
            return False

    async def check_multiple_permissions(
        self,
        user_id: str,
        permissions: List[str],
        role: str,
        tenant_id: Optional[str] = None,
        store_id: Optional[str] = None,
        warehouse_id: Optional[str] = None,
        require_all: bool = True,
    ) -> bool:
        """Check multiple permissions (AND or OR logic)."""
        try:
            permission_set = await self.get_user_permissions(
                user_id, role, tenant_id, store_id, warehouse_id
            )

            if require_all:
                return permission_set.has_all_permissions(permissions)
            else:
                return permission_set.has_any_permission(permissions)

        except Exception as e:
            logger.error(f"Multiple permission check failed: {str(e)}")
            return False

    async def grant_user_permission(
        self,
        user_id: str,
        permission: str,
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """Grant a specific permission to a user."""
        try:
            manager = await get_connection_manager()

            # Validate permission exists
            if permission not in CORELY_PERMISSIONS and not permission.endswith("*"):
                raise ValidationException(f"Invalid permission: {permission}")

            grant_data = {
                "user_id": user_id,
                "permission": permission,
                "granted_by": granted_by,
                "granted_at": datetime.now(timezone.utc),
                "expires_at": expires_at,
                "status": "active",
            }

            async with manager.get_collection("user_permission_grants") as collection:
                await collection.insert_one(grant_data)

            # Update user permissions collection
            async with manager.get_collection("user_permissions") as collection:
                await collection.update_one(
                    {"user_id": user_id},
                    {
                        "$addToSet": {"granted_permissions": permission},
                        "$set": {"updated_at": datetime.now(timezone.utc)},
                    },
                    upsert=True,
                )

            # Invalidate user's permission cache
            await self.invalidate_user_cache(user_id)

            logger.info(f"Granted permission {permission} to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to grant permission: {str(e)}")
            return False

    async def revoke_user_permission(
        self, user_id: str, permission: str, revoked_by: str
    ) -> bool:
        """Revoke a specific permission from a user."""
        try:
            manager = await get_connection_manager()

            # Mark grant as revoked
            async with manager.get_collection("user_permission_grants") as collection:
                await collection.update_many(
                    {"user_id": user_id, "permission": permission, "status": "active"},
                    {
                        "$set": {
                            "status": "revoked",
                            "revoked_by": revoked_by,
                            "revoked_at": datetime.now(timezone.utc),
                        }
                    },
                )

            # Update user permissions collection
            async with manager.get_collection("user_permissions") as collection:
                await collection.update_one(
                    {"user_id": user_id},
                    {
                        "$pull": {"granted_permissions": permission},
                        "$addToSet": {"revoked_permissions": permission},
                        "$set": {"updated_at": datetime.now(timezone.utc)},
                    },
                )

            # Invalidate user's permission cache
            await self.invalidate_user_cache(user_id)

            logger.info(f"Revoked permission {permission} from user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke permission: {str(e)}")
            return False

    async def bulk_grant_permissions(
        self, user_ids: List[str], permissions: List[str], granted_by: str
    ) -> Dict[str, bool]:
        """Grant multiple permissions to multiple users."""
        results = {}

        for user_id in user_ids:
            user_results = {}
            for permission in permissions:
                success = await self.grant_user_permission(
                    user_id, permission, granted_by
                )
                user_results[permission] = success

            results[user_id] = user_results

        return results

    async def get_permission_audit_log(
        self,
        user_id: Optional[str] = None,
        permission: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get audit log of permission changes."""
        try:
            manager = await get_connection_manager()

            # Build query
            query = {
                "granted_at": {
                    "$gte": datetime.now(timezone.utc) - timedelta(days=days)
                }
            }

            if user_id:
                query["user_id"] = user_id
            if permission:
                query["permission"] = permission

            audit_logs = []
            async with manager.get_collection("user_permission_grants") as collection:
                cursor = collection.find(query).sort("granted_at", -1)

                async for log_entry in cursor:
                    audit_logs.append(
                        {
                            "user_id": log_entry["user_id"],
                            "permission": log_entry["permission"],
                            "action": (
                                "revoked"
                                if log_entry["status"] == "revoked"
                                else "granted"
                            ),
                            "granted_by": log_entry.get("granted_by"),
                            "revoked_by": log_entry.get("revoked_by"),
                            "granted_at": log_entry["granted_at"].isoformat(),
                            "revoked_at": (
                                log_entry["revoked_at"].isoformat()
                                if log_entry.get("revoked_at")
                                else None
                            ),
                            "expires_at": (
                                log_entry["expires_at"].isoformat()
                                if log_entry.get("expires_at")
                                else None
                            ),
                            "status": log_entry["status"],
                        }
                    )

            return audit_logs

        except Exception as e:
            logger.error(f"Failed to get permission audit log: {str(e)}")
            return []

    async def create_permission_template(
        self,
        template_name: str,
        permissions: List[str],
        description: str,
        created_by: str,
    ) -> str:
        """Create a reusable permission template."""
        try:
            manager = await get_connection_manager()

            template_data = {
                "name": template_name,
                "permissions": permissions,
                "description": description,
                "created_by": created_by,
                "created_at": datetime.now(timezone.utc),
                "is_active": True,
            }

            async with manager.get_collection("permission_templates") as collection:
                result = await collection.insert_one(template_data)

                logger.info(f"Created permission template: {template_name}")
                return str(result.inserted_id)

        except Exception as e:
            logger.error(f"Failed to create permission template: {str(e)}")
            raise ValidationException("Failed to create permission template")

    async def apply_permission_template(
        self, template_id: str, user_ids: List[str], applied_by: str
    ) -> Dict[str, bool]:
        """Apply a permission template to multiple users."""
        try:
            manager = await get_connection_manager()

            # Get template
            async with manager.get_collection("permission_templates") as collection:
                template = await collection.find_one({"_id": template_id})

                if not template:
                    raise ValidationException("Template not found")

                if not template["is_active"]:
                    raise ValidationException("Template is not active")

            # Apply permissions to users
            results = await self.bulk_grant_permissions(
                user_ids, template["permissions"], applied_by
            )

            # Log template application
            application_log = {
                "template_id": template_id,
                "template_name": template["name"],
                "user_ids": user_ids,
                "applied_by": applied_by,
                "applied_at": datetime.now(timezone.utc),
                "permissions_count": len(template["permissions"]),
            }

            async with manager.get_collection("template_applications") as collection:
                await collection.insert_one(application_log)

            return results

        except Exception as e:
            logger.error(f"Failed to apply permission template: {str(e)}")
            return {user_id: False for user_id in user_ids}

    def get_available_permissions(self, module: Optional[str] = None) -> Dict[str, str]:
        """Get all available permissions, optionally filtered by module."""
        if module:
            return {
                perm: desc
                for perm, desc in CORELY_PERMISSIONS.items()
                if perm.startswith(f"{module}.")
            }

        return CORELY_PERMISSIONS.copy()

    def get_role_permissions_template(self, role: str) -> List[str]:
        """Get the permission template for a specific role."""
        return ROLE_PERMISSION_TEMPLATES.get(role, [])

    async def validate_permission_structure(self) -> Dict[str, Any]:
        """Validate the permission structure for consistency."""
        validation_results = {"valid": True, "issues": [], "statistics": {}}

        try:
            # Check for orphaned permissions in role templates
            all_defined_permissions = set(CORELY_PERMISSIONS.keys())
            used_permissions = set()

            for role, permissions in ROLE_PERMISSION_TEMPLATES.items():
                for perm in permissions:
                    if perm == "*":
                        used_permissions.update(all_defined_permissions)
                    elif perm.endswith("*"):
                        prefix = perm[:-1]
                        matching = [
                            p for p in all_defined_permissions if p.startswith(prefix)
                        ]
                        used_permissions.update(matching)
                    else:
                        used_permissions.add(perm)

            # Find permissions not used in any role
            unused_permissions = all_defined_permissions - used_permissions
            if unused_permissions:
                validation_results["issues"].append(
                    {
                        "type": "unused_permissions",
                        "count": len(unused_permissions),
                        "permissions": list(unused_permissions),
                    }
                )

            # Find permissions used in roles but not defined
            undefined_permissions = used_permissions - all_defined_permissions
            # Filter out wildcard patterns
            undefined_permissions = {
                p for p in undefined_permissions if not p.endswith("*") and p != "*"
            }

            if undefined_permissions:
                validation_results["valid"] = False
                validation_results["issues"].append(
                    {
                        "type": "undefined_permissions",
                        "count": len(undefined_permissions),
                        "permissions": list(undefined_permissions),
                    }
                )

            # Statistics
            validation_results["statistics"] = {
                "total_permissions": len(all_defined_permissions),
                "total_roles": len(ROLE_PERMISSION_TEMPLATES),
                "modules_covered": len(
                    set(p.split(".")[0] for p in all_defined_permissions)
                ),
                "unused_permissions_count": len(unused_permissions),
            }

            return validation_results

        except Exception as e:
            logger.error(f"Permission structure validation failed: {str(e)}")
            return {
                "valid": False,
                "issues": [{"type": "validation_error", "message": str(e)}],
                "statistics": {},
            }


# Global permission manager instance
_permission_manager: Optional[PermissionManager] = None


def get_permission_manager() -> PermissionManager:
    """Get global permission manager instance."""
    global _permission_manager
    if _permission_manager is None:
        _permission_manager = PermissionManager()
    return _permission_manager


# Convenience functions for permission checking
async def check_user_permission(
    user_id: str,
    permission: str,
    role: str,
    tenant_id: Optional[str] = None,
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
) -> bool:
    """Check if user has a specific permission."""
    manager = get_permission_manager()
    return await manager.check_permission(
        user_id, permission, role, tenant_id, store_id, warehouse_id
    )


async def get_user_effective_permissions(
    user_id: str,
    role: str,
    tenant_id: Optional[str] = None,
    store_id: Optional[str] = None,
    warehouse_id: Optional[str] = None,
) -> List[str]:
    """Get all effective permissions for a user."""
    manager = get_permission_manager()
    permission_set = await manager.get_user_permissions(
        user_id, role, tenant_id, store_id, warehouse_id
    )
    return permission_set.effective_permissions


async def grant_permission(user_id: str, permission: str, granted_by: str) -> bool:
    """Grant a permission to a user."""
    manager = get_permission_manager()
    return await manager.grant_user_permission(user_id, permission, granted_by)


async def revoke_permission(user_id: str, permission: str, revoked_by: str) -> bool:
    """Revoke a permission from a user."""
    manager = get_permission_manager()
    return await manager.revoke_user_permission(user_id, permission, revoked_by)


async def invalidate_user_permissions(user_id: str) -> None:
    """Invalidate cached permissions for a user."""
    manager = get_permission_manager()
    await manager.invalidate_user_cache(user_id)


# Database index management
async def ensure_permission_indexes() -> None:
    """Ensure permission-related indexes are created."""
    try:
        manager = await get_connection_manager()

        # User permissions collection
        async with manager.get_collection("user_permissions") as collection:
            await collection.create_index("user_id", unique=True, background=True)
            await collection.create_index("updated_at", background=True)

        # User permission grants collection
        async with manager.get_collection("user_permission_grants") as collection:
            await collection.create_index("user_id", background=True)
            await collection.create_index("permission", background=True)
            await collection.create_index("status", background=True)
            await collection.create_index("granted_at", background=True)
            await collection.create_index("expires_at", background=True)

            # Compound indexes
            await collection.create_index(
                [("user_id", 1), ("permission", 1), ("status", 1)], background=True
            )

            # TTL index for expired grants
            await collection.create_index(
                "expires_at",
                expireAfterSeconds=86400,  # 24 hours after expiration
                background=True,
            )

        # Permission templates collection
        async with manager.get_collection("permission_templates") as collection:
            await collection.create_index("name", background=True)
            await collection.create_index("created_by", background=True)
            await collection.create_index("is_active", background=True)
            await collection.create_index("created_at", background=True)

        # Template applications collection
        async with manager.get_collection("template_applications") as collection:
            await collection.create_index("template_id", background=True)
            await collection.create_index("applied_by", background=True)
            await collection.create_index("applied_at", background=True)

            # TTL index - keep application logs for 1 year
            await collection.create_index(
                "applied_at", expireAfterSeconds=31536000, background=True  # 365 days
            )

        logger.info("Permission management indexes ensured successfully")

    except Exception as e:
        logger.error(f"Failed to ensure permission indexes: {str(e)}")
        raise


# Export all classes and functions
__all__ = [
    # Enums
    "PermissionScope",
    "PermissionType",
    # Constants
    "CORELY_PERMISSIONS",
    "ROLE_PERMISSION_TEMPLATES",
    # Data Classes
    "Permission",
    "PermissionSet",
    # Core Classes
    "PermissionManager",
    # Global Functions
    "get_permission_manager",
    # Convenience Functions
    "check_user_permission",
    "get_user_effective_permissions",
    "grant_permission",
    "revoke_permission",
    "invalidate_user_permissions",
    "ensure_permission_indexes",
]
