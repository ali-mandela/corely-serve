"""
Enterprise Multi-Tenant Stores Management System Constants
This module contains all constant values for the stores management platform.
"""

from enum import Enum
from typing import Dict, List

EnvironmentConstants = {}


# HTTP Status Codes
class HTTPStatus:
    """Common HTTP status codes"""

    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    INTERNAL_SERVER_ERROR = 500


# Tenant Management Constants
class TenantConstants:
    """Multi-tenant system constants"""

    MAX_TENANTS_PER_ORGANIZATION = 100
    DEFAULT_TENANT_PLAN = "basic"
    TENANT_SUBDOMAIN_PATTERN = r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$"

    # Tenant status
    TENANT_STATUS_ACTIVE = "active"
    TENANT_STATUS_SUSPENDED = "suspended"
    TENANT_STATUS_TRIAL = "trial"
    TENANT_STATUS_EXPIRED = "expired"

    # Subscription plans
    PLAN_BASIC = "basic"
    PLAN_PROFESSIONAL = "professional"
    PLAN_ENTERPRISE = "enterprise"

    PLAN_LIMITS = {
        PLAN_BASIC: {
            "max_stores": 5,
            "max_employees": 50,
            "max_products": 1000,
            "max_warehouses": 2,
            "storage_gb": 10,
        },
        PLAN_PROFESSIONAL: {
            "max_stores": 25,
            "max_employees": 500,
            "max_products": 10000,
            "max_warehouses": 10,
            "storage_gb": 100,
        },
        PLAN_ENTERPRISE: {
            "max_stores": -1,  # unlimited
            "max_employees": -1,
            "max_products": -1,
            "max_warehouses": -1,
            "storage_gb": 1000,
        },
    }


# Authentication & Authorization Constants
class AuthConstants:
    """Authentication system constants"""

    ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours for enterprise
    REFRESH_TOKEN_EXPIRE_DAYS = 30
    ALGORITHM = "HS256"
    TOKEN_TYPE = "Bearer"

    # Password requirements (enterprise grade)
    MIN_PASSWORD_LENGTH = 12
    MAX_PASSWORD_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL_CHARS = True

    # Session management
    SESSION_EXPIRE_HOURS = 8
    MAX_SESSIONS_PER_USER = 3
    FORCE_LOGOUT_INACTIVE_DAYS = 30


# User Roles & Permissions
class RoleConstants:
    """User roles in the stores management system"""

    # Super admin (platform level)
    SUPER_ADMIN = "super_admin"

    # Tenant level roles
    TENANT_ADMIN = "tenant_admin"
    TENANT_MANAGER = "tenant_manager"

    # Store level roles
    STORE_MANAGER = "store_manager"
    ASSISTANT_MANAGER = "assistant_manager"
    SHIFT_SUPERVISOR = "shift_supervisor"
    CASHIER = "cashier"
    SALES_ASSOCIATE = "sales_associate"
    INVENTORY_CLERK = "inventory_clerk"

    # Warehouse roles
    WAREHOUSE_MANAGER = "warehouse_manager"
    WAREHOUSE_SUPERVISOR = "warehouse_supervisor"
    WAREHOUSE_OPERATOR = "warehouse_operator"

    # Customer service roles
    CUSTOMER_SERVICE_MANAGER = "customer_service_manager"
    CUSTOMER_SERVICE_REP = "customer_service_rep"

    # Analytics & Reporting
    BUSINESS_ANALYST = "business_analyst"
    FINANCIAL_ANALYST = "financial_analyst"

    # Customer role
    CUSTOMER = "customer"

    ROLE_HIERARCHY = {
        SUPER_ADMIN: 100,
        TENANT_ADMIN: 90,
        TENANT_MANAGER: 80,
        STORE_MANAGER: 70,
        WAREHOUSE_MANAGER: 70,
        ASSISTANT_MANAGER: 60,
        SHIFT_SUPERVISOR: 50,
        WAREHOUSE_SUPERVISOR: 50,
        CUSTOMER_SERVICE_MANAGER: 50,
        BUSINESS_ANALYST: 40,
        FINANCIAL_ANALYST: 40,
        CASHIER: 30,
        SALES_ASSOCIATE: 30,
        INVENTORY_CLERK: 30,
        WAREHOUSE_OPERATOR: 30,
        CUSTOMER_SERVICE_REP: 30,
        CUSTOMER: 10,
    }


# Store Management Constants
class StoreConstants:
    """Store operations constants"""

    # Store types
    STORE_TYPE_RETAIL = "retail"
    STORE_TYPE_OUTLET = "outlet"
    STORE_TYPE_FLAGSHIP = "flagship"
    STORE_TYPE_POP_UP = "pop_up"
    STORE_TYPE_ONLINE = "online"

    # Store status
    STORE_STATUS_ACTIVE = "active"
    STORE_STATUS_INACTIVE = "inactive"
    STORE_STATUS_MAINTENANCE = "maintenance"
    STORE_STATUS_TEMPORARILY_CLOSED = "temporarily_closed"
    STORE_STATUS_PERMANENTLY_CLOSED = "permanently_closed"

    # Operating hours
    DEFAULT_OPEN_TIME = "09:00"
    DEFAULT_CLOSE_TIME = "21:00"

    # Store size categories
    STORE_SIZE_SMALL = "small"  # < 1000 sq ft
    STORE_SIZE_MEDIUM = "medium"  # 1000-5000 sq ft
    STORE_SIZE_LARGE = "large"  # > 5000 sq ft


# Employee Management Constants
class EmployeeConstants:
    """Employee management constants"""

    # Employment types
    EMPLOYMENT_TYPE_FULL_TIME = "full_time"
    EMPLOYMENT_TYPE_PART_TIME = "part_time"
    EMPLOYMENT_TYPE_CONTRACT = "contract"
    EMPLOYMENT_TYPE_SEASONAL = "seasonal"
    EMPLOYMENT_TYPE_INTERN = "intern"

    # Employee status
    EMPLOYEE_STATUS_ACTIVE = "active"
    EMPLOYEE_STATUS_INACTIVE = "inactive"
    EMPLOYEE_STATUS_ON_LEAVE = "on_leave"
    EMPLOYEE_STATUS_SUSPENDED = "suspended"
    EMPLOYEE_STATUS_TERMINATED = "terminated"

    # Shift types
    SHIFT_TYPE_MORNING = "morning"  # 6AM-2PM
    SHIFT_TYPE_AFTERNOON = "afternoon"  # 2PM-10PM
    SHIFT_TYPE_EVENING = "evening"  # 10PM-6AM
    SHIFT_TYPE_SPLIT = "split"

    # Leave types
    LEAVE_TYPE_SICK = "sick"
    LEAVE_TYPE_VACATION = "vacation"
    LEAVE_TYPE_PERSONAL = "personal"
    LEAVE_TYPE_MATERNITY = "maternity"
    LEAVE_TYPE_PATERNITY = "paternity"
    LEAVE_TYPE_EMERGENCY = "emergency"


# Product & Inventory Constants
class ProductConstants:
    """Product and inventory management constants"""

    # Product categories
    CATEGORY_ELECTRONICS = "electronics"
    CATEGORY_CLOTHING = "clothing"
    CATEGORY_FOOD_BEVERAGE = "food_beverage"
    CATEGORY_HOME_GARDEN = "home_garden"
    CATEGORY_HEALTH_BEAUTY = "health_beauty"
    CATEGORY_SPORTS_OUTDOORS = "sports_outdoors"
    CATEGORY_BOOKS_MEDIA = "books_media"
    CATEGORY_TOYS_GAMES = "toys_games"

    # Product status
    PRODUCT_STATUS_ACTIVE = "active"
    PRODUCT_STATUS_INACTIVE = "inactive"
    PRODUCT_STATUS_DISCONTINUED = "discontinued"
    PRODUCT_STATUS_OUT_OF_STOCK = "out_of_stock"
    PRODUCT_STATUS_BACKORDERED = "backordered"

    # Inventory levels
    LOW_STOCK_THRESHOLD = 10
    CRITICAL_STOCK_THRESHOLD = 5
    OVERSTOCK_THRESHOLD = 1000

    # SKU pattern
    SKU_PATTERN = r"^[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}$"
    BARCODE_PATTERNS = {
        "UPC": r"^\d{12}$",
        "EAN": r"^\d{13}$",
        "CODE128": r"^[A-Za-z0-9\-\.\ \$\/\+\%]{1,48}$",
    }


# Warehouse Management Constants
class WarehouseConstants:
    """Warehouse operations constants"""

    # Warehouse types
    WAREHOUSE_TYPE_DISTRIBUTION = "distribution"
    WAREHOUSE_TYPE_FULFILLMENT = "fulfillment"
    WAREHOUSE_TYPE_REGIONAL = "regional"
    WAREHOUSE_TYPE_LOCAL = "local"

    # Warehouse zones
    ZONE_RECEIVING = "receiving"
    ZONE_STORAGE = "storage"
    ZONE_PICKING = "picking"
    ZONE_PACKING = "packing"
    ZONE_SHIPPING = "shipping"
    ZONE_RETURNS = "returns"

    # Storage types
    STORAGE_TYPE_BULK = "bulk"
    STORAGE_TYPE_RACK = "rack"
    STORAGE_TYPE_SHELF = "shelf"
    STORAGE_TYPE_FLOOR = "floor"
    STORAGE_TYPE_COLD = "cold"
    STORAGE_TYPE_HAZMAT = "hazmat"


# POS System Constants
class POSConstants:
    """Point of Sale system constants"""

    # Transaction types
    TRANSACTION_TYPE_SALE = "sale"
    TRANSACTION_TYPE_RETURN = "return"
    TRANSACTION_TYPE_EXCHANGE = "exchange"
    TRANSACTION_TYPE_VOID = "void"
    TRANSACTION_TYPE_REFUND = "refund"

    # Payment methods
    PAYMENT_METHOD_CASH = "cash"
    PAYMENT_METHOD_CREDIT_CARD = "credit_card"
    PAYMENT_METHOD_DEBIT_CARD = "debit_card"
    PAYMENT_METHOD_MOBILE_PAY = "mobile_pay"
    PAYMENT_METHOD_GIFT_CARD = "gift_card"
    PAYMENT_METHOD_STORE_CREDIT = "store_credit"
    PAYMENT_METHOD_CHECK = "check"

    # Transaction status
    TRANSACTION_STATUS_PENDING = "pending"
    TRANSACTION_STATUS_COMPLETED = "completed"
    TRANSACTION_STATUS_CANCELLED = "cancelled"
    TRANSACTION_STATUS_FAILED = "failed"
    TRANSACTION_STATUS_REFUNDED = "refunded"

    # Receipt types
    RECEIPT_TYPE_SALE = "sale"
    RECEIPT_TYPE_RETURN = "return"
    RECEIPT_TYPE_GIFT = "gift"


# Customer Management Constants
class CustomerConstants:
    """Customer management constants"""

    # Customer types
    CUSTOMER_TYPE_RETAIL = "retail"
    CUSTOMER_TYPE_WHOLESALE = "wholesale"
    CUSTOMER_TYPE_VIP = "vip"
    CUSTOMER_TYPE_MEMBER = "member"

    # Customer status
    CUSTOMER_STATUS_ACTIVE = "active"
    CUSTOMER_STATUS_INACTIVE = "inactive"
    CUSTOMER_STATUS_BLOCKED = "blocked"
    CUSTOMER_STATUS_VIP = "vip"

    # Loyalty program tiers
    LOYALTY_TIER_BRONZE = "bronze"
    LOYALTY_TIER_SILVER = "silver"
    LOYALTY_TIER_GOLD = "gold"
    LOYALTY_TIER_PLATINUM = "platinum"

    LOYALTY_POINTS_EARNING_RATE = {
        LOYALTY_TIER_BRONZE: 1,  # 1 point per $1
        LOYALTY_TIER_SILVER: 1.25,
        LOYALTY_TIER_GOLD: 1.5,
        LOYALTY_TIER_PLATINUM: 2,
    }


# Database Collections/Tables
class DatabaseConstants:
    """Database collection/table names"""

    # Core collections
    TENANTS = "tenants"
    USERS = "users"
    USER_SESSIONS = "user_sessions"
    AUDIT_LOGS = "audit_logs"

    # Store management
    STORES = "stores"
    STORE_LOCATIONS = "store_locations"
    STORE_HOURS = "store_hours"

    # Employee management
    EMPLOYEES = "employees"
    EMPLOYEE_SCHEDULES = "employee_schedules"
    EMPLOYEE_TIMESHEETS = "employee_timesheets"
    EMPLOYEE_LEAVES = "employee_leaves"

    # Product & Inventory
    PRODUCTS = "products"
    PRODUCT_CATEGORIES = "product_categories"
    INVENTORY = "inventory"
    INVENTORY_MOVEMENTS = "inventory_movements"
    STOCK_ADJUSTMENTS = "stock_adjustments"

    # Warehouse
    WAREHOUSES = "warehouses"
    WAREHOUSE_ZONES = "warehouse_zones"
    WAREHOUSE_LOCATIONS = "warehouse_locations"

    # POS & Transactions
    TRANSACTIONS = "transactions"
    TRANSACTION_ITEMS = "transaction_items"
    PAYMENTS = "payments"
    RECEIPTS = "receipts"

    # Customer management
    CUSTOMERS = "customers"
    CUSTOMER_ADDRESSES = "customer_addresses"
    LOYALTY_ACCOUNTS = "loyalty_accounts"
    LOYALTY_TRANSACTIONS = "loyalty_transactions"

    # Reporting & Analytics
    SALES_REPORTS = "sales_reports"
    INVENTORY_REPORTS = "inventory_reports"
    EMPLOYEE_PERFORMANCE = "employee_performance"


# API Rate Limiting
class RateLimitConstants:
    """API rate limiting for enterprise system"""

    # General API limits
    DEFAULT_RATE_LIMIT = "1000/hour"
    AUTH_RATE_LIMIT = "20/minute"

    # Role-based limits
    SUPER_ADMIN_LIMIT = "10000/hour"
    TENANT_ADMIN_LIMIT = "5000/hour"
    STORE_MANAGER_LIMIT = "2000/hour"
    EMPLOYEE_LIMIT = "500/hour"
    CUSTOMER_LIMIT = "100/hour"

    # Operation-specific limits
    POS_TRANSACTION_LIMIT = "1000/hour"
    INVENTORY_UPDATE_LIMIT = "2000/hour"
    REPORT_GENERATION_LIMIT = "50/hour"


# Business Rules Constants
class BusinessConstants:
    """Business logic constants"""

    # Pagination
    DEFAULT_PAGE_SIZE = 25
    MAX_PAGE_SIZE = 100

    # Timeouts
    REPORT_GENERATION_TIMEOUT = 300  # 5 minutes
    BULK_OPERATION_TIMEOUT = 600  # 10 minutes

    # File uploads
    MAX_PRODUCT_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_BULK_IMPORT_SIZE = 50 * 1024 * 1024  # 50MB

    # Notification thresholds
    LOW_STOCK_NOTIFICATION_THRESHOLD = 10
    HIGH_VALUE_TRANSACTION_THRESHOLD = 1000
    DAILY_SALES_TARGET_VARIANCE = 0.2  # 20%


# Error Messages
class ErrorMessages:
    """Enterprise system error messages"""

    # Authentication
    INVALID_CREDENTIALS = "Invalid username or password"
    ACCOUNT_LOCKED = "Account has been locked due to multiple failed attempts"
    TENANT_SUSPENDED = "Tenant account is suspended"
    INSUFFICIENT_PERMISSIONS = "You don't have permission to perform this action"

    # Tenant limits
    TENANT_STORE_LIMIT_EXCEEDED = "Maximum number of stores reached for your plan"
    TENANT_EMPLOYEE_LIMIT_EXCEEDED = "Maximum number of employees reached for your plan"
    TENANT_STORAGE_LIMIT_EXCEEDED = "Storage limit exceeded for your plan"

    # Business operations
    INSUFFICIENT_INVENTORY = "Insufficient inventory for this transaction"
    STORE_CLOSED = "Store is currently closed"
    EMPLOYEE_NOT_SCHEDULED = "Employee is not scheduled for this time"
    INVALID_TRANSACTION = "Invalid transaction data"

    # Data validation
    INVALID_SKU = "Invalid SKU format"
    INVALID_BARCODE = "Invalid barcode format"
    DUPLICATE_PRODUCT = "Product with this SKU already exists"
    INVALID_STORE_HOURS = "Invalid store operating hours"


# Success Messages
class SuccessMessages:
    """Enterprise system success messages"""

    STORE_CREATED = "Store created successfully"
    EMPLOYEE_ADDED = "Employee added successfully"
    PRODUCT_UPDATED = "Product updated successfully"
    INVENTORY_ADJUSTED = "Inventory adjusted successfully"
    TRANSACTION_COMPLETED = "Transaction completed successfully"
    REPORT_GENERATED = "Report generated successfully"
    SCHEDULE_UPDATED = "Schedule updated successfully"


# Notification Types
class NotificationTypes:
    """System notification types"""

    LOW_STOCK_ALERT = "low_stock_alert"
    HIGH_VALUE_TRANSACTION = "high_value_transaction"
    EMPLOYEE_CLOCK_IN = "employee_clock_in"
    SHIFT_REMINDER = "shift_reminder"
    INVENTORY_REORDER = "inventory_reorder"
    SYSTEM_MAINTENANCE = "system_maintenance"
    PAYMENT_FAILED = "payment_failed"
    CUSTOMER_BIRTHDAY = "customer_birthday"


# Export all constants
__all__ = [
    "HTTPStatus",
    "TenantConstants",
    "AuthConstants",
    "RoleConstants",
    "StoreConstants",
    "EmployeeConstants",
    "ProductConstants",
    "WarehouseConstants",
    "POSConstants",
    "CustomerConstants",
    "DatabaseConstants",
    "RateLimitConstants",
    "BusinessConstants",
    "ErrorMessages",
    "SuccessMessages",
    "NotificationTypes",
]
