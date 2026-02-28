"""
Production-grade dependencies management for FastAPI

This module provides comprehensive dependency injection including:
- Authentication and authorization
- Database connections and sessions
- Permission checks and access control
- Rate limiting and validation
- Common request handling utilities
"""

# Authentication dependencies
from .auth import (
    get_current_user,
    get_current_active_user,
    get_current_superuser,
    get_optional_user,
    require_roles,
    require_permissions,
    TenantRequired,
    RateLimitRequired,
    security,
    tenant_required,
    rate_limit_standard,
    rate_limit_strict,
    require_admin,
    require_moderator,
    require_user_read,
    require_user_write,
    require_tenant_admin,
    require_system_admin
)

# Database dependencies
from .database import (
    get_db,
    get_session,
    get_collection,
    get_users_collection,
    get_tenants_collection,
    get_stores_collection,
    get_employees_collection,
    get_products_collection,
    get_inventory_collection,
    get_transactions_collection,
    get_audit_logs_collection,
    TenantDatabase,
    check_db_health,
    Pagination,
    get_pagination,
    SearchFilter,
    get_search_filter,
    tenant_db
)

# Permission dependencies
from .permissions import (
    PermissionChecker,
    ResourcePermissionChecker,
    # User permissions
    can_read_users,
    can_create_users,
    can_update_users,
    can_delete_users,
    # Store permissions
    can_read_stores,
    can_create_stores,
    can_update_stores,
    can_delete_stores,
    can_manage_stores,
    # Product permissions
    can_read_products,
    can_create_products,
    can_update_products,
    can_delete_products,
    can_manage_inventory,
    # Employee permissions
    can_read_employees,
    can_create_employees,
    can_update_employees,
    can_delete_employees,
    can_manage_schedules,
    # Transaction permissions
    can_read_transactions,
    can_create_transactions,
    can_refund_transactions,
    can_void_transactions,
    # Reporting permissions
    can_view_reports,
    can_export_reports,
    can_view_analytics,
    # Admin permissions
    can_manage_settings,
    can_manage_integrations,
    can_view_audit_logs,
    can_manage_roles,
    can_manage_permissions,
    # Tenant admin permissions
    can_manage_tenant,
    can_view_tenant_analytics,
    can_manage_billing,
    # System admin permissions
    can_manage_system,
    can_view_system_health,
    can_manage_maintenance,
    # Access checkers
    StoreAccessChecker,
    TenantAccessChecker,
    store_access_required,
    tenant_access_required,
    # Permission utilities
    require_any_permission,
    require_all_permissions,
    ConditionalPermission,
    BusinessHoursChecker,
    business_hours_required,
    business_hours_optional
)

# Common dependencies
from .common import (
    get_request_id,
    get_client_ip,
    get_user_agent,
    get_correlation_id,
    RequestContext,
    get_request_context,
    validate_json_content_type,
    APIVersion,
    api_v1,
    api_v2,
    health_check,
    EnvironmentCheck,
    dev_only,
    dev_test_only,
    prod_only,
    RequestSizeLimiter,
    small_request_limit,
    medium_request_limit,
    large_request_limit,
    FeatureFlag,
    new_ui_enabled,
    advanced_analytics,
    beta_features,
    get_timezone,
    get_locale,
    DeviceType,
    get_device_type
)

__all__ = [
    # Authentication
    "get_current_user",
    "get_current_active_user",
    "get_current_superuser",
    "get_optional_user",
    "require_roles",
    "require_permissions",
    "TenantRequired",
    "RateLimitRequired",
    "security",
    "tenant_required",
    "rate_limit_standard",
    "rate_limit_strict",
    "require_admin",
    "require_moderator",
    "require_user_read",
    "require_user_write",
    "require_tenant_admin",
    "require_system_admin",

    # Database
    "get_db",
    "get_session",
    "get_collection",
    "get_users_collection",
    "get_tenants_collection",
    "get_stores_collection",
    "get_employees_collection",
    "get_products_collection",
    "get_inventory_collection",
    "get_transactions_collection",
    "get_audit_logs_collection",
    "TenantDatabase",
    "check_db_health",
    "Pagination",
    "get_pagination",
    "SearchFilter",
    "get_search_filter",
    "tenant_db",

    # Permissions
    "PermissionChecker",
    "ResourcePermissionChecker",
    "can_read_users",
    "can_create_users",
    "can_update_users",
    "can_delete_users",
    "can_read_stores",
    "can_create_stores",
    "can_update_stores",
    "can_delete_stores",
    "can_manage_stores",
    "can_read_products",
    "can_create_products",
    "can_update_products",
    "can_delete_products",
    "can_manage_inventory",
    "can_read_employees",
    "can_create_employees",
    "can_update_employees",
    "can_delete_employees",
    "can_manage_schedules",
    "can_read_transactions",
    "can_create_transactions",
    "can_refund_transactions",
    "can_void_transactions",
    "can_view_reports",
    "can_export_reports",
    "can_view_analytics",
    "can_manage_settings",
    "can_manage_integrations",
    "can_view_audit_logs",
    "can_manage_roles",
    "can_manage_permissions",
    "can_manage_tenant",
    "can_view_tenant_analytics",
    "can_manage_billing",
    "can_manage_system",
    "can_view_system_health",
    "can_manage_maintenance",
    "StoreAccessChecker",
    "TenantAccessChecker",
    "store_access_required",
    "tenant_access_required",
    "require_any_permission",
    "require_all_permissions",
    "ConditionalPermission",
    "BusinessHoursChecker",
    "business_hours_required",
    "business_hours_optional",

    # Common
    "get_request_id",
    "get_client_ip",
    "get_user_agent",
    "get_correlation_id",
    "RequestContext",
    "get_request_context",
    "validate_json_content_type",
    "APIVersion",
    "api_v1",
    "api_v2",
    "health_check",
    "EnvironmentCheck",
    "dev_only",
    "dev_test_only",
    "prod_only",
    "RequestSizeLimiter",
    "small_request_limit",
    "medium_request_limit",
    "large_request_limit",
    "FeatureFlag",
    "new_ui_enabled",
    "advanced_analytics",
    "beta_features",
    "get_timezone",
    "get_locale",
    "DeviceType",
    "get_device_type",
]

# Version info
__version__ = "1.0.0"
__author__ = "Enterprise Development Team"