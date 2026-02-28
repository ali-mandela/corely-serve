"""
Enterprise Multi-Tenant Stores Management System - Utils Module
This module provides all utility functions, constants, exceptions, validators, and formatters.
"""

# Version info
__version__ = "1.0.0"
__author__ = "Enterprise Stores Management Team"
__description__ = (
    "Utility functions for India-based enterprise stores management system"
)

# Import all constants
from .utils.constants import (
    # Core constants
    HTTPStatus,
    TenantConstants,
    AuthConstants,
    RoleConstants,
    # Business domain constants
    StoreConstants,
    EmployeeConstants,
    ProductConstants,
    WarehouseConstants,
    POSConstants,
    CustomerConstants,
    # System constants
    DatabaseConstants,
    RateLimitConstants,
    BusinessConstants,
    # Validation constants
    # ValidationConstants,
    # SecurityConstants,
    # TransportConstants,
    # EnvironmentConstants,
    # Messages
    ErrorMessages,
    SuccessMessages,
    NotificationTypes,
    # Patterns and API
    # RegexPatterns,
    # APIConstants,
    # CacheConstants,
)

# Import all exceptions
from .utils.exceptions import (
    # Base exception
    BaseAppException,
    # Authentication & Authorization
    AuthenticationException,
    InvalidCredentialsException,
    TokenExpiredException,
    TokenInvalidException,
    AccountLockedException,
    AuthorizationException,
    InsufficientPermissionsException,
    TenantAccessDeniedException,
    # Tenant Management
    TenantException,
    TenantSuspendedException,
    TenantLimitExceededException,
    TenantNotFoundException,
    # Store Management
    StoreException,
    StoreNotFoundException,
    StoreClosedException,
    InvalidStoreHoursException,
    # Employee Management
    EmployeeException,
    EmployeeNotFoundException,
    EmployeeNotScheduledException,
    DuplicateEmployeeException,
    InvalidShiftException,
    # Product & Inventory
    ProductException,
    ProductNotFoundException,
    DuplicateProductException,
    InvalidSKUException,
    InvalidBarcodeException,
    InventoryException,
    InsufficientInventoryException,
    InvalidInventoryAdjustmentException,
    # POS & Transactions
    TransactionException,
    InvalidTransactionException,
    PaymentFailedException,
    TransactionNotFoundException,
    RefundException,
    # Customer Management
    CustomerException,
    CustomerNotFoundException,
    DuplicateCustomerException,
    CustomerBlockedException,
    # Warehouse
    WarehouseException,
    WarehouseNotFoundException,
    InvalidWarehouseLocationException,
    # Validation
    ValidationException,
    RequiredFieldException,
    InvalidEmailException,
    InvalidPhoneException,
    # File Operations
    FileException,
    FileTooLargeException,
    InvalidFileTypeException,
    # System
    RateLimitExceededException,
    DatabaseException,
    RecordNotFoundException,
    DuplicateRecordException,
    DatabaseConnectionException,
)

# Import all helper functions
from .utils.helpers import (
    # String utilities
    generate_id,
    generate_tenant_subdomain,
    generate_sku,
    generate_employee_id,
    sanitize_string,
    slugify,
    # Validation utilities
    validate_email,
    validate_phone,
    validate_sku,
    validate_barcode,
    validate_store_hours,
    validate_gstin,
    validate_pan,
    validate_aadhaar,
    validate_ifsc,
    # Date & time utilities
    get_current_utc,
    format_datetime,
    parse_datetime,
    is_business_hours,
    get_shift_hours,
    calculate_age,
    get_week_boundaries,
    get_indian_business_hours,
    is_indian_holiday,
    get_indian_timezone,
    convert_to_ist,
    # Financial utilities
    format_currency,
    format_inr_currency,
    calculate_gst,
    calculate_discount,
    calculate_loyalty_points,
    # Inventory utilities
    calculate_reorder_point,
    categorize_stock_level,
    calculate_inventory_turnover,
    # Pagination utilities
    paginate_query,
    # Security utilities
    generate_secure_token,
    hash_data,
    mask_sensitive_data,
    generate_correlation_id,
    # Data transformation utilities
    flatten_dict,
    unflatten_dict,
    deep_merge_dicts,
    safe_json_loads,
    safe_json_dumps,
    # File utilities
    get_file_extension,
    is_allowed_file_type,
    format_file_size,
    # Search & filter utilities
    build_search_query,
    apply_filters,
    # Business logic helpers
    calculate_shift_duration,
    is_peak_hours,
    calculate_commission,
)

# Import all validators
from .utils.validators import (
    # Core validation
    ValidationResult,
    # Validator classes
    BasicValidators,
    IndianDocumentValidators,
    ContactValidators,
    BusinessValidators,
    EmployeeValidators,
    CustomerValidators,
    DateTimeValidators,
    ComplexValidators,
    PasswordValidators,
)

# Import all formatters
from .utils.formatters import (
    # Format enums
    DateFormat,
    # Formatter classes
    CurrencyFormatter,
    DateTimeFormatter,
    ContactFormatter,
    BusinessFormatter,
    DocumentFormatter,
    ReportFormatter,
    UtilityFormatter,
)

# Convenience imports - Most commonly used functions
# These can be imported directly from core.utils
from .utils.helpers import (
    generate_id as create_id,
    format_currency as format_money,
    validate_email as is_valid_email,
    validate_phone as is_valid_phone,
    generate_secure_token as create_token,
)

from .utils.formatters import CurrencyFormatter, DocumentFormatter

from .utils.validators import ValidationResult


# ================== UTILITY FUNCTIONS ==================


def get_module_info() -> dict:
    """Get information about the utils module"""
    return {
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "modules": ["constants", "exceptions", "helpers", "validators", "formatters"],
        "total_constants": len(
            [name for name in globals() if name.endswith("Constants")]
        ),
        "total_exceptions": len(
            [name for name in globals() if name.endswith("Exception")]
        ),
        "india_specific_features": [
            "GST calculations",
            "Indian mobile validation",
            "GSTIN/PAN/Aadhaar validation",
            "INR currency formatting",
            "Indian business hours",
            "Indian address formatting",
        ],
    }


def validate_system_health() -> dict:
    """Validate that all utility modules are working correctly"""
    health_status = {"status": "healthy", "modules": {}, "errors": []}

    try:
        # Test constants
        assert HTTPStatus.OK == 200
        assert TenantConstants.PLAN_BASIC == "basic"
        health_status["modules"]["constants"] = "OK"
    except Exception as e:
        health_status["modules"]["constants"] = "ERROR"
        health_status["errors"].append(f"Constants error: {str(e)}")

    try:
        # Test exceptions
        exc = BaseAppException("test")
        assert exc.message == "test"
        health_status["modules"]["exceptions"] = "OK"
    except Exception as e:
        health_status["modules"]["exceptions"] = "ERROR"
        health_status["errors"].append(f"Exceptions error: {str(e)}")

    try:
        # Test helpers
        assert validate_email("test@example.com") == True
        assert validate_email("invalid-email") == False
        health_status["modules"]["helpers"] = "OK"
    except Exception as e:
        health_status["modules"]["helpers"] = "ERROR"
        health_status["errors"].append(f"Helpers error: {str(e)}")

    try:
        # Test validators
        result = BasicValidators.required("test", "field")
        assert result.is_valid == True
        health_status["modules"]["validators"] = "OK"
    except Exception as e:
        health_status["modules"]["validators"] = "ERROR"
        health_status["errors"].append(f"Validators error: {str(e)}")

    try:
        # Test formatters
        formatted = CurrencyFormatter.format_inr(1000)
        assert "₹" in formatted
        health_status["modules"]["formatters"] = "OK"
    except Exception as e:
        health_status["modules"]["formatters"] = "ERROR"
        health_status["errors"].append(f"Formatters error: {str(e)}")

    if health_status["errors"]:
        health_status["status"] = "unhealthy"

    return health_status


# ================== CONVENIENCE FUNCTIONS ==================


def quick_validate(data: dict, validation_type: str) -> ValidationResult:
    """Quick validation for common data types"""
    if validation_type == "tenant":
        return ComplexValidators.tenant_data(data)
    elif validation_type == "store":
        return ComplexValidators.store_data(data)
    elif validation_type == "employee":
        return ComplexValidators.employee_data(data)
    elif validation_type == "email":
        return ContactValidators.email(data.get("email", ""))
    elif validation_type == "mobile":
        return ContactValidators.indian_mobile(data.get("mobile", ""))
    elif validation_type == "gstin":
        return IndianDocumentValidators.gstin(data.get("gstin", ""))
    else:
        result = ValidationResult()
        result.add_error(f"Unknown validation type: {validation_type}")
        return result


def quick_format(value, format_type: str, **kwargs):
    """Quick formatting for common data types"""
    if format_type == "currency" or format_type == "inr":
        return CurrencyFormatter.format_inr(value, **kwargs)
    elif format_type == "mobile":
        return ContactFormatter.format_indian_mobile(value, **kwargs)
    elif format_type == "gstin":
        return DocumentFormatter.format_gstin(value)
    elif format_type == "pan":
        return DocumentFormatter.format_pan(value)
    elif format_type == "aadhaar":
        return DocumentFormatter.format_aadhaar(value, **kwargs)
    elif format_type == "date":
        format_enum = kwargs.get("format", DateFormat.INDIAN)
        return DateTimeFormatter.format_date(value, format_enum)
    elif format_type == "percentage":
        return ReportFormatter.format_percentage(value, **kwargs)
    else:
        return str(value)


def create_error_response(exception: BaseAppException) -> dict:
    """Create standardized error response from exception"""
    return {
        "success": False,
        "error": {
            "code": exception.error_code,
            "message": exception.message,
            "details": exception.details,
            "status_code": exception.status_code,
        },
        "data": None,
    }


def create_success_response(data=None, message: str = "Operation successful") -> dict:
    """Create standardized success response"""
    return {"success": True, "error": None, "message": message, "data": data}


# Export commonly used items for easy access
__all__ = [
    # Module info
    "get_module_info",
    "validate_system_health",
    # Quick utilities
    "quick_validate",
    "quick_format",
    "create_error_response",
    "create_success_response",
    # Most commonly used constants
    "HTTPStatus",
    "TenantConstants",
    "StoreConstants",
    "EmployeeConstants",
    "ProductConstants",
    "ErrorMessages",
    "SuccessMessages",
    # Most commonly used exceptions
    "BaseAppException",
    "ValidationException",
    "AuthenticationException",
    "AuthorizationException",
    "TenantLimitExceededException",
    "InsufficientInventoryException",
    # Most commonly used helpers
    "generate_id",
    "validate_email",
    "validate_phone",
    "validate_gstin",
    "format_currency",
    "calculate_gst",
    "generate_secure_token",
    # Most commonly used validators
    "ValidationResult",
    "BasicValidators",
    "IndianDocumentValidators",
    "ContactValidators",
    "ComplexValidators",
    # Most commonly used formatters
    "CurrencyFormatter",
    "DocumentFormatter",
    "ContactFormatter",
    "DateTimeFormatter",
    # Convenience aliases
    "create_id",
    "format_money",
    "is_valid_email",
    "is_valid_phone",
    "create_token",
]


# Module initialization message
def _init_message():
    """Print initialization message in development"""
    import os

    if os.getenv("ENVIRONMENT", "development") == "development":
        print(f"✅ Core Utils Module v{__version__} initialized successfully")
        print(f"🇮🇳 India-specific features enabled")
        print(f"📦 Loaded: Constants, Exceptions, Helpers, Validators, Formatters")


# Call init message
_init_message()
