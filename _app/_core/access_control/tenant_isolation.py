"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Production-Optimized Tenant Isolation Module

This module provides comprehensive tenant isolation for multi-tenant operations,
integrating with the new authentication system and providing high-performance
data access control with complete audit trails.

Features:
- Integration with AuthenticationContext
- High-performance MongoDB operations with caching
- Comprehensive audit logging
- ABAC policy integration
- Store and warehouse context isolation
- Real-time security monitoring
- Performance optimization with connection pooling
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List, Set, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from functools import lru_cache
import time

from bson import ObjectId
from fastapi import HTTPException, status, Request, Depends
from functools import wraps

from app._core.auth.enhanced_auth import AuthenticationContext, get_current_user
from app._core.database.connection import get_connection_manager
from app._core.database.session_manager import create_session, create_transaction
from app._core.audit.logger import log_security_event, log_data_event
from app._core.audit.models import AuditEventType, AuditSeverity
from app._core.utils.exceptions import AuthorizationException, SecurityException
from app._core.utils.constants import DatabaseConstants


logger = logging.getLogger(__name__)


class TenantAccessLevel(Enum):
    """Tenant access levels for different operations"""

    NONE = "none"
    READ_ONLY = "read_only"
    FULL_ACCESS = "full_access"
    ADMIN_ACCESS = "admin_access"


class IsolationViolationType(Enum):
    """Types of tenant isolation violations"""

    CROSS_TENANT_ACCESS = "cross_tenant_access"
    UNAUTHORIZED_STORE_ACCESS = "unauthorized_store_access"
    UNAUTHORIZED_WAREHOUSE_ACCESS = "unauthorized_warehouse_access"
    MISSING_TENANT_CONTEXT = "missing_tenant_context"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class TenantContext:
    """Enhanced tenant context with retail-specific attributes"""

    tenant_id: str
    user_id: str
    user_role: str
    role_level: int
    store_id: Optional[str] = None
    warehouse_id: Optional[str] = None
    department_id: Optional[str] = None
    enabled_modules: Set[str] = field(default_factory=set)
    permissions: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def can_access_store(self, target_store_id: str) -> bool:
        """Check if user can access target store"""
        # Super admin and tenant admin can access all stores
        if self.role_level >= 90:  # TENANT_ADMIN level
            return True

        # Store-specific access
        if self.store_id:
            return self.store_id == target_store_id

        return False

    def can_access_warehouse(self, target_warehouse_id: str) -> bool:
        """Check if user can access target warehouse"""
        # Super admin and tenant admin can access all warehouses
        if self.role_level >= 90:  # TENANT_ADMIN level
            return True

        # Warehouse-specific access
        if self.warehouse_id:
            return self.warehouse_id == target_warehouse_id

        return False

    def get_access_level(self) -> TenantAccessLevel:
        """Get user's access level within tenant"""
        if self.role_level >= 100:  # SUPER_ADMIN
            return TenantAccessLevel.ADMIN_ACCESS
        elif self.role_level >= 70:  # Manager level and above
            return TenantAccessLevel.FULL_ACCESS
        elif self.role_level >= 30:  # Employee level
            return TenantAccessLevel.READ_ONLY
        else:
            return TenantAccessLevel.NONE


class TenantIsolationError(Exception):
    """Exception raised when tenant isolation is violated"""

    def __init__(
        self,
        message: str,
        violation_type: IsolationViolationType,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_info: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.violation_type = violation_type
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.resource_info = resource_info or {}
        self.timestamp = datetime.now(timezone.utc)


class TenantDataFilter:
    """Advanced database query filter for tenant isolation with caching"""

    def __init__(self):
        self._filter_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = asyncio.Lock()
        self._cache_ttl = 300  # 5 minutes
        self._cache_cleanup_task: Optional[asyncio.Task] = None

    async def add_tenant_filter(
        self,
        query: Dict[str, Any],
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
        resource_type: Optional[str] = None,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
    ) -> Dict[str, Any]:
        """
        Add comprehensive tenant filter to database queries

        Args:
            query: Original MongoDB query
            tenant_context: Current tenant context
            allow_cross_tenant: Whether to allow cross-tenant access
            resource_type: Type of resource being accessed
            store_isolation: Whether to enforce store-level isolation
            warehouse_isolation: Whether to enforce warehouse-level isolation

        Returns:
            Modified query with tenant isolation filters
        """

        # Create cache key for performance
        cache_key = self._create_cache_key(
            tenant_context,
            allow_cross_tenant,
            resource_type,
            store_isolation,
            warehouse_isolation,
        )

        # Check cache first
        cached_filter = await self._get_cached_filter(cache_key)
        if cached_filter:
            query.update(cached_filter)
            return query

        # Build tenant filter
        tenant_filter = {}

        # Basic tenant isolation
        if not allow_cross_tenant and tenant_context.role_level < 100:
            if "tenant_id" not in query:
                tenant_filter["tenant_id"] = tenant_context.tenant_id
            elif query.get("tenant_id") != tenant_context.tenant_id:
                raise TenantIsolationError(
                    f"Cross-tenant access denied: {tenant_context.tenant_id} -> {query.get('tenant_id')}",
                    IsolationViolationType.CROSS_TENANT_ACCESS,
                    tenant_context.tenant_id,
                    tenant_context.user_id,
                    {"attempted_tenant": query.get("tenant_id")},
                )

        # Store-level isolation
        if store_isolation and tenant_context.store_id:
            if tenant_context.role_level < 70:  # Below manager level
                tenant_filter["store_id"] = tenant_context.store_id

        # Warehouse-level isolation
        if warehouse_isolation and tenant_context.warehouse_id:
            if tenant_context.role_level < 70:  # Below manager level
                tenant_filter["warehouse_id"] = tenant_context.warehouse_id

        # Department-level isolation (if applicable)
        if tenant_context.department_id and resource_type in ["employee", "schedule"]:
            if tenant_context.role_level < 50:  # Below supervisor level
                tenant_filter["department_id"] = tenant_context.department_id

        # Cache the filter
        await self._cache_filter(cache_key, tenant_filter)

        # Apply filter to query
        query.update(tenant_filter)
        return query

    def validate_tenant_access(
        self,
        resource_tenant_id: str,
        tenant_context: TenantContext,
        resource_type: Optional[str] = None,
    ) -> bool:
        """
        Validate if user can access resource from specific tenant

        Args:
            resource_tenant_id: Tenant ID of the resource
            tenant_context: Current tenant context
            resource_type: Type of resource being accessed

        Returns:
            True if access is allowed, False otherwise
        """
        # Super admins can access all tenants
        if tenant_context.role_level >= 100:
            return True

        # Same tenant access is always allowed
        if resource_tenant_id == tenant_context.tenant_id:
            return True

        # Different tenant access is denied by default
        return False

    async def filter_cross_tenant_data(
        self,
        data: List[Dict[str, Any]],
        tenant_context: TenantContext,
        resource_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Filter out data that belongs to different tenants

        Args:
            data: List of data items to filter
            tenant_context: Current tenant context
            resource_type: Type of resource being filtered

        Returns:
            Filtered data list
        """
        if tenant_context.role_level >= 100:  # Super admin sees all
            return data

        filtered_data = []
        for item in data:
            item_tenant_id = item.get("tenant_id")

            if item_tenant_id:
                if self.validate_tenant_access(
                    item_tenant_id, tenant_context, resource_type
                ):
                    filtered_data.append(item)
            else:
                # Include items without tenant_id (global resources)
                filtered_data.append(item)

        return filtered_data

    def _create_cache_key(
        self,
        tenant_context: TenantContext,
        allow_cross_tenant: bool,
        resource_type: Optional[str],
        store_isolation: bool,
        warehouse_isolation: bool,
    ) -> str:
        """Create cache key for filter caching"""
        key_parts = [
            tenant_context.tenant_id,
            str(tenant_context.role_level),
            str(allow_cross_tenant),
            resource_type or "none",
            str(store_isolation),
            str(warehouse_isolation),
            tenant_context.store_id or "none",
            tenant_context.warehouse_id or "none",
        ]

        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()

    async def _get_cached_filter(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached filter if not expired"""
        async with self._cache_lock:
            cached_entry = self._filter_cache.get(cache_key)

            if cached_entry and cached_entry["expires_at"] > time.time():
                return cached_entry["filter"]

            # Remove expired entry
            if cached_entry:
                self._filter_cache.pop(cache_key, None)

            return None

    async def _cache_filter(self, cache_key: str, filter_data: Dict[str, Any]) -> None:
        """Cache filter for future use"""
        async with self._cache_lock:
            self._filter_cache[cache_key] = {
                "filter": filter_data,
                "expires_at": time.time() + self._cache_ttl,
                "created_at": time.time(),
            }


class TenantAwareDatabase:
    """High-performance database wrapper with comprehensive tenant isolation"""

    def __init__(self):
        self.data_filter = TenantDataFilter()
        self._operation_metrics = {
            "read_operations": 0,
            "write_operations": 0,
            "isolation_violations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

    async def find_one(
        self,
        collection_name: str,
        query: Dict[str, Any],
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
        projection: Optional[Dict[str, int]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find one document with comprehensive tenant isolation"""
        start_time = time.time()

        try:
            # Add tenant filter
            filtered_query = await self.data_filter.add_tenant_filter(
                query.copy(),
                tenant_context,
                allow_cross_tenant,
                self._get_resource_type(collection_name),
                store_isolation,
                warehouse_isolation,
            )

            # Execute query using connection manager
            manager = await get_connection_manager()
            async with manager.get_collection(collection_name) as collection:
                result = await collection.find_one(filtered_query, projection)

            # Update metrics
            self._operation_metrics["read_operations"] += 1

            # Log data access
            await log_data_event(
                user_id=tenant_context.user_id,
                operation="read",
                resource_type=collection_name,
                resource_id=str(result.get("_id")) if result else None,
                success=result is not None,
                tenant_id=tenant_context.tenant_id,
                data_count=1 if result else 0,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

            return result

        except TenantIsolationError as e:
            await self._handle_isolation_violation(e, tenant_context, "find_one")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "tenant_isolation_violation",
                    "message": "Access denied: Tenant isolation violation",
                    "violation_type": e.violation_type.value,
                },
            )
        except Exception as e:
            logger.error(f"Database find_one error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed",
            )

    async def find_many(
        self,
        collection_name: str,
        query: Dict[str, Any],
        tenant_context: TenantContext,
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        sort: Optional[List] = None,
        projection: Optional[Dict[str, int]] = None,
        allow_cross_tenant: bool = False,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
    ) -> List[Dict[str, Any]]:
        """Find multiple documents with tenant isolation"""
        start_time = time.time()

        try:
            # Add tenant filter
            filtered_query = await self.data_filter.add_tenant_filter(
                query.copy(),
                tenant_context,
                allow_cross_tenant,
                self._get_resource_type(collection_name),
                store_isolation,
                warehouse_isolation,
            )

            # Execute query
            manager = await get_connection_manager()
            async with manager.get_collection(collection_name) as collection:
                cursor = collection.find(filtered_query, projection)

                if sort:
                    cursor = cursor.sort(sort)
                if skip:
                    cursor = cursor.skip(skip)
                if limit:
                    cursor = cursor.limit(limit)

                results = await cursor.to_list(length=None)

            # Update metrics
            self._operation_metrics["read_operations"] += 1

            # Log data access
            await log_data_event(
                user_id=tenant_context.user_id,
                operation="read",
                resource_type=collection_name,
                success=True,
                tenant_id=tenant_context.tenant_id,
                data_count=len(results),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

            return results

        except TenantIsolationError as e:
            await self._handle_isolation_violation(e, tenant_context, "find_many")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "tenant_isolation_violation",
                    "message": "Access denied: Tenant isolation violation",
                    "violation_type": e.violation_type.value,
                },
            )

    async def insert_one(
        self,
        collection_name: str,
        document: Dict[str, Any],
        tenant_context: TenantContext,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
    ) -> str:
        """Insert document with tenant isolation and audit fields"""
        start_time = time.time()

        try:
            # Ensure document has proper tenant context
            await self._ensure_tenant_context(
                document, tenant_context, store_isolation, warehouse_isolation
            )

            # Add audit fields
            self._add_audit_fields(document, tenant_context, "create")

            # Execute insert using transaction
            async with create_session(tenant_context.tenant_id) as session:
                async with create_transaction(session) as transaction:
                    manager = await get_connection_manager()
                    async with manager.get_collection(collection_name) as collection:
                        result = await collection.insert_one(
                            document, session=transaction.session_ctx.session
                        )

            # Update metrics
            self._operation_metrics["write_operations"] += 1

            # Log data creation
            await log_data_event(
                user_id=tenant_context.user_id,
                operation="create",
                resource_type=collection_name,
                resource_id=str(result.inserted_id),
                success=True,
                tenant_id=tenant_context.tenant_id,
                data_count=1,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

            return str(result.inserted_id)

        except TenantIsolationError as e:
            await self._handle_isolation_violation(e, tenant_context, "insert_one")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "tenant_isolation_violation",
                    "message": "Cannot insert data with invalid tenant context",
                },
            )

    async def update_one(
        self,
        collection_name: str,
        query: Dict[str, Any],
        update: Dict[str, Any],
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
        upsert: bool = False,
    ) -> bool:
        """Update document with tenant isolation"""
        start_time = time.time()

        try:
            # Add tenant filter to query
            filtered_query = await self.data_filter.add_tenant_filter(
                query.copy(),
                tenant_context,
                allow_cross_tenant,
                self._get_resource_type(collection_name),
                store_isolation,
                warehouse_isolation,
            )

            # Add audit fields to update
            self._add_audit_fields_to_update(update, tenant_context, "update")

            # Execute update using transaction
            async with create_session(tenant_context.tenant_id) as session:
                async with create_transaction(session) as transaction:
                    manager = await get_connection_manager()
                    async with manager.get_collection(collection_name) as collection:
                        result = await collection.update_one(
                            filtered_query,
                            update,
                            upsert=upsert,
                            session=transaction.session_ctx.session,
                        )

            # Update metrics
            self._operation_metrics["write_operations"] += 1

            # Log data update
            await log_data_event(
                user_id=tenant_context.user_id,
                operation="update",
                resource_type=collection_name,
                success=result.modified_count > 0,
                tenant_id=tenant_context.tenant_id,
                data_count=result.modified_count,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

            return result.modified_count > 0

        except TenantIsolationError as e:
            await self._handle_isolation_violation(e, tenant_context, "update_one")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "tenant_isolation_violation",
                    "message": "Access denied: Tenant isolation violation",
                },
            )

    async def delete_one(
        self,
        collection_name: str,
        query: Dict[str, Any],
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
        store_isolation: bool = False,
        warehouse_isolation: bool = False,
    ) -> bool:
        """Delete document with tenant isolation"""
        start_time = time.time()

        try:
            # Add tenant filter
            filtered_query = await self.data_filter.add_tenant_filter(
                query.copy(),
                tenant_context,
                allow_cross_tenant,
                self._get_resource_type(collection_name),
                store_isolation,
                warehouse_isolation,
            )

            # Execute delete using transaction
            async with create_session(tenant_context.tenant_id) as session:
                async with create_transaction(session) as transaction:
                    manager = await get_connection_manager()
                    async with manager.get_collection(collection_name) as collection:
                        result = await collection.delete_one(
                            filtered_query, session=transaction.session_ctx.session
                        )

            # Update metrics
            self._operation_metrics["write_operations"] += 1

            # Log data deletion
            await log_data_event(
                user_id=tenant_context.user_id,
                operation="delete",
                resource_type=collection_name,
                success=result.deleted_count > 0,
                tenant_id=tenant_context.tenant_id,
                data_count=result.deleted_count,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

            return result.deleted_count > 0

        except TenantIsolationError as e:
            await self._handle_isolation_violation(e, tenant_context, "delete_one")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "tenant_isolation_violation",
                    "message": "Access denied: Tenant isolation violation",
                },
            )

    async def _ensure_tenant_context(
        self,
        document: Dict[str, Any],
        tenant_context: TenantContext,
        store_isolation: bool,
        warehouse_isolation: bool,
    ) -> None:
        """Ensure document has proper tenant context"""

        # Set tenant_id
        if "tenant_id" not in document:
            document["tenant_id"] = tenant_context.tenant_id
        elif (
            document["tenant_id"] != tenant_context.tenant_id
            and tenant_context.role_level < 100
        ):
            raise TenantIsolationError(
                f"Cannot create document for different tenant: {document['tenant_id']}",
                IsolationViolationType.CROSS_TENANT_ACCESS,
                tenant_context.tenant_id,
                tenant_context.user_id,
                {"attempted_tenant": document["tenant_id"]},
            )

        # Set store context if required
        if store_isolation and tenant_context.store_id:
            if "store_id" not in document:
                document["store_id"] = tenant_context.store_id

        # Set warehouse context if required
        if warehouse_isolation and tenant_context.warehouse_id:
            if "warehouse_id" not in document:
                document["warehouse_id"] = tenant_context.warehouse_id

    def _add_audit_fields(
        self, document: Dict[str, Any], tenant_context: TenantContext, operation: str
    ) -> None:
        """Add audit fields to document"""
        now = datetime.now(timezone.utc)
        document.update(
            {
                "created_by": tenant_context.user_id,
                "created_at": now,
                "updated_by": tenant_context.user_id,
                "updated_at": now,
                "version": 1,
            }
        )

    def _add_audit_fields_to_update(
        self, update: Dict[str, Any], tenant_context: TenantContext, operation: str
    ) -> None:
        """Add audit fields to update operation"""
        if "$set" not in update:
            update["$set"] = {}

        update["$set"]["updated_by"] = tenant_context.user_id
        update["$set"]["updated_at"] = datetime.now(timezone.utc)

        if "$inc" not in update:
            update["$inc"] = {}
        update["$inc"]["version"] = 1

    def _get_resource_type(self, collection_name: str) -> str:
        """Extract resource type from collection name"""
        # Remove tenant prefix if present
        if "_" in collection_name:
            parts = collection_name.split("_")
            return parts[-1]  # Last part is usually the resource type
        return collection_name

    async def _handle_isolation_violation(
        self, error: TenantIsolationError, tenant_context: TenantContext, operation: str
    ) -> None:
        """Handle tenant isolation violations with logging and metrics"""
        self._operation_metrics["isolation_violations"] += 1

        # Log security event
        await log_security_event(
            event_type=AuditEventType.DATA_BREACH_ATTEMPT,
            description=f"Tenant isolation violation in {operation}: {str(error)}",
            user_id=tenant_context.user_id,
            ip_address="unknown",  # Could be extracted from request context
            severity=AuditSeverity.CRITICAL,
            tenant_id=tenant_context.tenant_id,
            additional_data={
                "violation_type": error.violation_type.value,
                "operation": operation,
                "resource_info": error.resource_info,
                "timestamp": error.timestamp.isoformat(),
            },
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Get database operation metrics"""
        return self._operation_metrics.copy()


# Enhanced dependency injection for FastAPI
async def get_tenant_context(
    current_user: AuthenticationContext = Depends(get_current_user),
) -> TenantContext:
    """Extract enhanced tenant context from authenticated request"""

    if not current_user.tenant_id and current_user.role_level < 100:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "missing_tenant_context",
                "message": "User not associated with any tenant",
            },
        )

    return TenantContext(
        tenant_id=current_user.tenant_id or "global",
        user_id=current_user.user_id,
        user_role=current_user.role,
        role_level=current_user.role_level,
        store_id=current_user.store_id,
        warehouse_id=current_user.warehouse_id,
        department_id=current_user.department_id,
        enabled_modules=current_user.enabled_modules,
        permissions=current_user.permissions,
        session_id=current_user.session_id,
    )


# Enhanced decorators for tenant isolation
def require_tenant_isolation(
    allow_cross_tenant: bool = False,
    store_isolation: bool = False,
    warehouse_isolation: bool = False,
    min_role_level: int = 0,
):
    """Enhanced decorator to enforce tenant isolation on endpoints"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract tenant context from kwargs
            tenant_context = kwargs.get("tenant_context")
            if not isinstance(tenant_context, TenantContext):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Tenant context not found or invalid",
                )

            # Check minimum role level
            if tenant_context.role_level < min_role_level:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "insufficient_privileges",
                        "message": f"Minimum role level {min_role_level} required",
                        "current_level": tenant_context.role_level,
                    },
                )

            # Store isolation parameters in context
            tenant_context.allow_cross_tenant = allow_cross_tenant
            tenant_context.store_isolation = store_isolation
            tenant_context.warehouse_isolation = warehouse_isolation

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Global tenant-aware database instance
_tenant_database: Optional[TenantAwareDatabase] = None


def get_tenant_database() -> TenantAwareDatabase:
    """Get global tenant-aware database instance"""
    global _tenant_database
    if _tenant_database is None:
        _tenant_database = TenantAwareDatabase()
    return _tenant_database


# Convenience service class
class TenantAwareService:
    """Enhanced base service class with comprehensive tenant isolation"""

    def __init__(self):
        self.db = get_tenant_database()

    async def find_by_id(
        self,
        collection_name: str,
        doc_id: str,
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Find document by ID with tenant isolation"""
        return await self.db.find_one(
            collection_name=collection_name,
            query={"_id": ObjectId(doc_id)},
            tenant_context=tenant_context,
            allow_cross_tenant=allow_cross_tenant,
        )

    async def find_all(
        self,
        collection_name: str,
        tenant_context: TenantContext,
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
        skip: Optional[int] = None,
        sort: Optional[List] = None,
        store_isolation: bool = False,
    ) -> List[Dict[str, Any]]:
        """Find all documents with tenant isolation"""
        query = filters or {}
        return await self.db.find_many(
            collection_name=collection_name,
            query=query,
            tenant_context=tenant_context,
            limit=limit,
            skip=skip,
            sort=sort,
            store_isolation=store_isolation,
        )

    async def create(
        self,
        collection_name: str,
        data: Dict[str, Any],
        tenant_context: TenantContext,
        store_isolation: bool = False,
    ) -> str:
        """Create document with tenant isolation"""
        return await self.db.insert_one(
            collection_name=collection_name,
            document=data,
            tenant_context=tenant_context,
            store_isolation=store_isolation,
        )

    async def update(
        self,
        collection_name: str,
        doc_id: str,
        data: Dict[str, Any],
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
    ) -> bool:
        """Update document with tenant isolation"""
        return await self.db.update_one(
            collection_name=collection_name,
            query={"_id": ObjectId(doc_id)},
            update={"$set": data},
            tenant_context=tenant_context,
            allow_cross_tenant=allow_cross_tenant,
        )

    async def delete(
        self,
        collection_name: str,
        doc_id: str,
        tenant_context: TenantContext,
        allow_cross_tenant: bool = False,
    ) -> bool:
        """Delete document with tenant isolation"""
        return await self.db.delete_one(
            collection_name=collection_name,
            query={"_id": ObjectId(doc_id)},
            tenant_context=tenant_context,
            allow_cross_tenant=allow_cross_tenant,
        )


# Database index management for tenant isolation
async def ensure_tenant_isolation_indexes() -> None:
    """Ensure proper indexes for tenant isolation performance"""
    try:
        manager = await get_connection_manager()

        # Get all collection names
        async with manager.get_database() as db:
            collections = await db.list_collection_names()

            # Create tenant isolation indexes for each collection
            for collection_name in collections:
                if collection_name.startswith("system."):
                    continue  # Skip system collections

                async with manager.get_collection(collection_name) as collection:
                    # Create tenant_id index if collection has tenant_id field
                    try:
                        await collection.create_index("tenant_id", background=True)
                    except Exception:
                        pass  # Collection might not have tenant_id field

                    # Create compound indexes for common query patterns
                    try:
                        await collection.create_index(
                            [("tenant_id", 1), ("created_at", -1)], background=True
                        )
                    except Exception:
                        pass

                    # Store-specific indexes
                    try:
                        await collection.create_index(
                            [("tenant_id", 1), ("store_id", 1)], background=True
                        )
                    except Exception:
                        pass

                    # Warehouse-specific indexes
                    try:
                        await collection.create_index(
                            [("tenant_id", 1), ("warehouse_id", 1)], background=True
                        )
                    except Exception:
                        pass

        logger.info("Tenant isolation indexes ensured successfully")

    except Exception as e:
        logger.error(f"Failed to ensure tenant isolation indexes: {str(e)}")
        raise


# Performance monitoring utilities
async def get_tenant_isolation_metrics() -> Dict[str, Any]:
    """Get tenant isolation performance metrics"""
    try:
        db = get_tenant_database()
        metrics = db.get_metrics()

        # Add cache metrics
        cache_total = metrics["cache_hits"] + metrics["cache_misses"]
        cache_hit_rate = (
            (metrics["cache_hits"] / cache_total * 100) if cache_total > 0 else 0
        )

        return {
            **metrics,
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "total_operations": metrics["read_operations"]
            + metrics["write_operations"],
            "isolation_violation_rate": (
                (
                    metrics["isolation_violations"]
                    / max(1, metrics["read_operations"] + metrics["write_operations"])
                )
                * 100
            ),
        }

    except Exception as e:
        logger.error(f"Failed to get tenant isolation metrics: {str(e)}")
        return {"error": str(e)}


# Security monitoring utilities
async def check_tenant_security_violations(
    tenant_id: str, hours: int = 24
) -> List[Dict[str, Any]]:
    """Check for tenant security violations in the specified time period"""
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        manager = await get_connection_manager()
        violations = []

        async with manager.get_collection("security_events") as collection:
            cursor = collection.find(
                {
                    "tenant_id": tenant_id,
                    "event_type": "DATA_BREACH_ATTEMPT",
                    "timestamp": {"$gte": cutoff_time},
                }
            ).sort("timestamp", -1)

            async for violation in cursor:
                violations.append(
                    {
                        "timestamp": violation["timestamp"].isoformat(),
                        "user_id": violation["user_id"],
                        "description": violation["description"],
                        "severity": violation["severity"],
                        "additional_data": violation.get("additional_data", {}),
                    }
                )

        return violations

    except Exception as e:
        logger.error(f"Failed to check security violations: {str(e)}")
        return []


# Export all tenant isolation functionality
__all__ = [
    # Enums
    "TenantAccessLevel",
    "IsolationViolationType",
    # Data Classes
    "TenantContext",
    # Exceptions
    "TenantIsolationError",
    # Core Classes
    "TenantDataFilter",
    "TenantAwareDatabase",
    "TenantAwareService",
    # Dependencies
    "get_tenant_context",
    # Decorators
    "require_tenant_isolation",
    # Utilities
    "get_tenant_database",
    "ensure_tenant_isolation_indexes",
    "get_tenant_isolation_metrics",
    "check_tenant_security_violations",
]
