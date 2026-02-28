"""
Enterprise Multi-Tenant Stores Management System Exceptions
This module contains all custom exception classes for the stores management platform.
"""

from typing import Optional, Dict, Any, List
from app._core.utils.constants import HTTPStatus, ErrorMessages


class BaseAppException(Exception):
    """Base exception class for all application exceptions"""

    def __init__(
        self,
        message: str,
        status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
        }


# ================== AUTHENTICATION & AUTHORIZATION EXCEPTIONS ==================


class AuthenticationException(BaseAppException):
    """Base class for authentication-related exceptions"""

    def __init__(self, message: str = ErrorMessages.INVALID_CREDENTIALS, **kwargs):
        super().__init__(message, HTTPStatus.UNAUTHORIZED, **kwargs)


class InvalidCredentialsException(AuthenticationException):
    """Raised when user provides invalid login credentials"""

    def __init__(self, message: str = ErrorMessages.INVALID_CREDENTIALS):
        super().__init__(message, error_code="INVALID_CREDENTIALS")


class TokenExpiredException(AuthenticationException):
    """Raised when authentication token has expired"""

    def __init__(self, message: str = "Authentication token has expired"):
        super().__init__(message, error_code="TOKEN_EXPIRED")


class TokenInvalidException(AuthenticationException):
    """Raised when authentication token is invalid"""

    def __init__(self, message: str = "Invalid authentication token"):
        super().__init__(message, error_code="TOKEN_INVALID")


class AccountLockedException(AuthenticationException):
    """Raised when user account is locked"""

    def __init__(
        self,
        message: str = ErrorMessages.ACCOUNT_LOCKED,
        lockout_duration: Optional[int] = None,
    ):
        details = (
            {"lockout_duration_minutes": lockout_duration} if lockout_duration else {}
        )
        super().__init__(message, error_code="ACCOUNT_LOCKED", details=details)


class AuthorizationException(BaseAppException):
    """Base class for authorization-related exceptions"""

    def __init__(self, message: str = ErrorMessages.INSUFFICIENT_PERMISSIONS, **kwargs):
        super().__init__(message, HTTPStatus.FORBIDDEN, **kwargs)


class InsufficientPermissionsException(AuthorizationException):
    """Raised when user lacks required permissions"""

    def __init__(self, required_permission: str, user_role: str):
        message = (
            f"Role '{user_role}' lacks required permission '{required_permission}'"
        )
        details = {"required_permission": required_permission, "user_role": user_role}
        super().__init__(
            message, error_code="INSUFFICIENT_PERMISSIONS", details=details
        )


class TenantAccessDeniedException(AuthorizationException):
    """Raised when user tries to access a tenant they don't belong to"""

    def __init__(self, tenant_id: str, user_id: str):
        message = f"User does not have access to tenant '{tenant_id}'"
        details = {"tenant_id": tenant_id, "user_id": user_id}
        super().__init__(message, error_code="TENANT_ACCESS_DENIED", details=details)


# ================== TENANT MANAGEMENT EXCEPTIONS ==================


class TenantException(BaseAppException):
    """Base class for tenant-related exceptions"""

    pass


class TenantSuspendedException(TenantException):
    """Raised when trying to access a suspended tenant"""

    def __init__(self, tenant_id: str, reason: Optional[str] = None):
        message = ErrorMessages.TENANT_SUSPENDED
        details = {"tenant_id": tenant_id}
        if reason:
            details["suspension_reason"] = reason
        super().__init__(message, HTTPStatus.FORBIDDEN, "TENANT_SUSPENDED", details)


class TenantLimitExceededException(TenantException):
    """Raised when tenant exceeds their plan limits"""

    def __init__(
        self, limit_type: str, current_count: int, max_allowed: int, plan: str
    ):
        message = f"Tenant has exceeded {limit_type} limit for {plan} plan"
        details = {
            "limit_type": limit_type,
            "current_count": current_count,
            "max_allowed": max_allowed,
            "plan": plan,
        }
        super().__init__(
            message, HTTPStatus.FORBIDDEN, "TENANT_LIMIT_EXCEEDED", details
        )


class TenantNotFoundException(TenantException):
    """Raised when tenant is not found"""

    def __init__(self, tenant_id: str):
        message = f"Tenant '{tenant_id}' not found"
        details = {"tenant_id": tenant_id}
        super().__init__(message, HTTPStatus.NOT_FOUND, "TENANT_NOT_FOUND", details)


# ================== STORE MANAGEMENT EXCEPTIONS ==================


class StoreException(BaseAppException):
    """Base class for store-related exceptions"""

    pass


class StoreNotFoundException(StoreException):
    """Raised when store is not found"""

    def __init__(self, store_id: str):
        message = f"Store '{store_id}' not found"
        details = {"store_id": store_id}
        super().__init__(message, HTTPStatus.NOT_FOUND, "STORE_NOT_FOUND", details)


class StoreClosedException(StoreException):
    """Raised when attempting operations on a closed store"""

    def __init__(self, store_id: str, store_status: str):
        message = ErrorMessages.STORE_CLOSED
        details = {"store_id": store_id, "status": store_status}
        super().__init__(message, HTTPStatus.CONFLICT, "STORE_CLOSED", details)


class InvalidStoreHoursException(StoreException):
    """Raised when store hours are invalid"""

    def __init__(self, open_time: str, close_time: str):
        message = ErrorMessages.INVALID_STORE_HOURS
        details = {"open_time": open_time, "close_time": close_time}
        super().__init__(
            message, HTTPStatus.BAD_REQUEST, "INVALID_STORE_HOURS", details
        )


# ================== EMPLOYEE MANAGEMENT EXCEPTIONS ==================


class EmployeeException(BaseAppException):
    """Base class for employee-related exceptions"""

    pass


class EmployeeNotFoundException(EmployeeException):
    """Raised when employee is not found"""

    def __init__(self, employee_id: str):
        message = f"Employee '{employee_id}' not found"
        details = {"employee_id": employee_id}
        super().__init__(message, HTTPStatus.NOT_FOUND, "EMPLOYEE_NOT_FOUND", details)


class EmployeeNotScheduledException(EmployeeException):
    """Raised when employee is not scheduled for requested time"""

    def __init__(self, employee_id: str, requested_time: str):
        message = ErrorMessages.EMPLOYEE_NOT_SCHEDULED
        details = {"employee_id": employee_id, "requested_time": requested_time}
        super().__init__(
            message, HTTPStatus.CONFLICT, "EMPLOYEE_NOT_SCHEDULED", details
        )


class DuplicateEmployeeException(EmployeeException):
    """Raised when trying to create duplicate employee"""

    def __init__(self, identifier: str, identifier_type: str = "email"):
        message = f"Employee with {identifier_type} '{identifier}' already exists"
        details = {identifier_type: identifier}
        super().__init__(message, HTTPStatus.CONFLICT, "DUPLICATE_EMPLOYEE", details)


class InvalidShiftException(EmployeeException):
    """Raised when shift scheduling is invalid"""

    def __init__(self, reason: str, shift_details: Dict[str, Any]):
        message = f"Invalid shift: {reason}"
        super().__init__(
            message, HTTPStatus.BAD_REQUEST, "INVALID_SHIFT", shift_details
        )


# ================== PRODUCT & INVENTORY EXCEPTIONS ==================


class ProductException(BaseAppException):
    """Base class for product-related exceptions"""

    pass


class ProductNotFoundException(ProductException):
    """Raised when product is not found"""

    def __init__(self, identifier: str, identifier_type: str = "id"):
        message = f"Product with {identifier_type} '{identifier}' not found"
        details = {identifier_type: identifier}
        super().__init__(message, HTTPStatus.NOT_FOUND, "PRODUCT_NOT_FOUND", details)


class DuplicateProductException(ProductException):
    """Raised when trying to create duplicate product"""

    def __init__(self, sku: str):
        message = ErrorMessages.DUPLICATE_PRODUCT
        details = {"sku": sku}
        super().__init__(message, HTTPStatus.CONFLICT, "DUPLICATE_PRODUCT", details)


class InvalidSKUException(ProductException):
    """Raised when SKU format is invalid"""

    def __init__(self, sku: str):
        message = ErrorMessages.INVALID_SKU
        details = {"sku": sku}
        super().__init__(message, HTTPStatus.BAD_REQUEST, "INVALID_SKU", details)


class InvalidBarcodeException(ProductException):
    """Raised when barcode format is invalid"""

    def __init__(self, barcode: str, barcode_type: str):
        message = ErrorMessages.INVALID_BARCODE
        details = {"barcode": barcode, "barcode_type": barcode_type}
        super().__init__(message, HTTPStatus.BAD_REQUEST, "INVALID_BARCODE", details)


class InventoryException(BaseAppException):
    """Base class for inventory-related exceptions"""

    pass


class InsufficientInventoryException(InventoryException):
    """Raised when there's insufficient inventory for operation"""

    def __init__(
        self, product_id: str, requested: int, available: int, location: str = None
    ):
        message = ErrorMessages.INSUFFICIENT_INVENTORY
        details = {
            "product_id": product_id,
            "requested_quantity": requested,
            "available_quantity": available,
        }
        if location:
            details["location"] = location
        super().__init__(
            message, HTTPStatus.CONFLICT, "INSUFFICIENT_INVENTORY", details
        )


class InvalidInventoryAdjustmentException(InventoryException):
    """Raised when inventory adjustment is invalid"""

    def __init__(self, reason: str, adjustment_details: Dict[str, Any]):
        message = f"Invalid inventory adjustment: {reason}"
        super().__init__(
            message,
            HTTPStatus.BAD_REQUEST,
            "INVALID_INVENTORY_ADJUSTMENT",
            adjustment_details,
        )


# ================== POS & TRANSACTION EXCEPTIONS ==================


class TransactionException(BaseAppException):
    """Base class for transaction-related exceptions"""

    pass


class InvalidTransactionException(TransactionException):
    """Raised when transaction data is invalid"""

    def __init__(
        self, reason: str, transaction_details: Optional[Dict[str, Any]] = None
    ):
        message = f"{ErrorMessages.INVALID_TRANSACTION}: {reason}"
        super().__init__(
            message,
            HTTPStatus.BAD_REQUEST,
            "INVALID_TRANSACTION",
            transaction_details or {},
        )


class PaymentFailedException(TransactionException):
    """Raised when payment processing fails"""

    def __init__(
        self, payment_method: str, reason: str, transaction_id: Optional[str] = None
    ):
        message = f"Payment failed via {payment_method}: {reason}"
        details = {"payment_method": payment_method, "failure_reason": reason}
        if transaction_id:
            details["transaction_id"] = transaction_id
        super().__init__(
            message, HTTPStatus.PAYMENT_REQUIRED, "PAYMENT_FAILED", details
        )


class TransactionNotFoundException(TransactionException):
    """Raised when transaction is not found"""

    def __init__(self, transaction_id: str):
        message = f"Transaction '{transaction_id}' not found"
        details = {"transaction_id": transaction_id}
        super().__init__(
            message, HTTPStatus.NOT_FOUND, "TRANSACTION_NOT_FOUND", details
        )


class RefundException(TransactionException):
    """Raised when refund cannot be processed"""

    def __init__(self, reason: str, transaction_id: str, refund_amount: float):
        message = f"Refund failed: {reason}"
        details = {"transaction_id": transaction_id, "refund_amount": refund_amount}
        super().__init__(message, HTTPStatus.CONFLICT, "REFUND_FAILED", details)


# ================== CUSTOMER MANAGEMENT EXCEPTIONS ==================


class CustomerException(BaseAppException):
    """Base class for customer-related exceptions"""

    pass


class CustomerNotFoundException(CustomerException):
    """Raised when customer is not found"""

    def __init__(self, identifier: str, identifier_type: str = "id"):
        message = f"Customer with {identifier_type} '{identifier}' not found"
        details = {identifier_type: identifier}
        super().__init__(message, HTTPStatus.NOT_FOUND, "CUSTOMER_NOT_FOUND", details)


class DuplicateCustomerException(CustomerException):
    """Raised when trying to create duplicate customer"""

    def __init__(self, email: str):
        message = f"Customer with email '{email}' already exists"
        details = {"email": email}
        super().__init__(message, HTTPStatus.CONFLICT, "DUPLICATE_CUSTOMER", details)


class CustomerBlockedException(CustomerException):
    """Raised when customer account is blocked"""

    def __init__(self, customer_id: str, reason: Optional[str] = None):
        message = "Customer account is blocked"
        details = {"customer_id": customer_id}
        if reason:
            details["block_reason"] = reason
        super().__init__(message, HTTPStatus.FORBIDDEN, "CUSTOMER_BLOCKED", details)


# ================== WAREHOUSE EXCEPTIONS ==================


class WarehouseException(BaseAppException):
    """Base class for warehouse-related exceptions"""

    pass


class WarehouseNotFoundException(WarehouseException):
    """Raised when warehouse is not found"""

    def __init__(self, warehouse_id: str):
        message = f"Warehouse '{warehouse_id}' not found"
        details = {"warehouse_id": warehouse_id}
        super().__init__(message, HTTPStatus.NOT_FOUND, "WAREHOUSE_NOT_FOUND", details)


class InvalidWarehouseLocationException(WarehouseException):
    """Raised when warehouse location is invalid"""

    def __init__(self, location: str, warehouse_id: str):
        message = (
            f"Invalid warehouse location '{location}' in warehouse '{warehouse_id}'"
        )
        details = {"location": location, "warehouse_id": warehouse_id}
        super().__init__(
            message, HTTPStatus.BAD_REQUEST, "INVALID_WAREHOUSE_LOCATION", details
        )


# ================== VALIDATION EXCEPTIONS ==================


class ValidationException(BaseAppException):
    """Base class for validation errors"""

    def __init__(
        self, message: str, field_errors: Optional[Dict[str, List[str]]] = None
    ):
        details = {"field_errors": field_errors} if field_errors else {}
        super().__init__(
            message, HTTPStatus.UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", details
        )


class RequiredFieldException(ValidationException):
    """Raised when required field is missing"""

    def __init__(self, field_name: str):
        message = f"Required field '{field_name}' is missing"
        field_errors = {field_name: [ErrorMessages.REQUIRED_FIELD]}
        super().__init__(message, field_errors)


class InvalidEmailException(ValidationException):
    """Raised when email format is invalid"""

    def __init__(self, email: str):
        message = ErrorMessages.INVALID_EMAIL
        field_errors = {"email": [message]}
        super().__init__(message, field_errors)


class InvalidPhoneException(ValidationException):
    """Raised when phone number format is invalid"""

    def __init__(self, phone: str):
        message = ErrorMessages.INVALID_PHONE
        field_errors = {"phone": [message]}
        super().__init__(message, field_errors)


# ================== FILE & UPLOAD EXCEPTIONS ==================


class FileException(BaseAppException):
    """Base class for file-related exceptions"""

    pass


class FileTooLargeException(FileException):
    """Raised when uploaded file exceeds size limit"""

    def __init__(self, filename: str, file_size: int, max_size: int):
        message = ErrorMessages.FILE_TOO_LARGE
        details = {"filename": filename, "file_size": file_size, "max_size": max_size}
        super().__init__(message, HTTPStatus.BAD_REQUEST, "FILE_TOO_LARGE", details)


class InvalidFileTypeException(FileException):
    """Raised when file type is not allowed"""

    def __init__(self, filename: str, file_type: str, allowed_types: List[str]):
        message = ErrorMessages.INVALID_FILE_TYPE
        details = {
            "filename": filename,
            "file_type": file_type,
            "allowed_types": allowed_types,
        }
        super().__init__(message, HTTPStatus.BAD_REQUEST, "INVALID_FILE_TYPE", details)


# ================== RATE LIMITING EXCEPTIONS ==================


class RateLimitExceededException(BaseAppException):
    """Raised when API rate limit is exceeded"""

    def __init__(self, limit: str, retry_after: Optional[int] = None):
        message = f"Rate limit exceeded: {limit}"
        details = {"rate_limit": limit}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(
            message, HTTPStatus.TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED", details
        )


# ================== DATABASE EXCEPTIONS ==================


class DatabaseException(BaseAppException):
    """Base class for database-related exceptions"""

    def __init__(self, message: str = "Errir NoiT Found", **kwargs):
        # def __init__(self, message: str = ErrorMessages.DATABASE_ERROR if ErrorMessages.DATABASE_ERROR else 'ERROR NIT FOUND', **kwargs):
        super().__init__(message, HTTPStatus.INTERNAL_SERVER_ERROR, **kwargs)


class RecordNotFoundException(DatabaseException):
    """Raised when database record is not found"""

    def __init__(self, model: str, identifier: str):
        message = f"{model} with identifier '{identifier}' not found"
        details = {"model": model, "identifier": identifier}
        super().__init__(message, HTTPStatus.NOT_FOUND, "RECORD_NOT_FOUND", details)


class DuplicateRecordException(DatabaseException):
    """Raised when trying to create duplicate record"""

    def __init__(self, model: str, field: str, value: str):
        message = f"{model} with {field} '{value}' already exists"
        details = {"model": model, "field": field, "value": value}
        super().__init__(message, HTTPStatus.CONFLICT, "DUPLICATE_RECORD", details)


class DatabaseConnectionException(DatabaseException):
    """Raised when database connection fails"""

    def __init__(self, database_name: str):
        message = f"Failed to connect to database '{database_name}'"
        details = {"database": database_name}
        super().__init__(
            message, error_code="DATABASE_CONNECTION_FAILED", details=details
        )


# Export all exception classes
__all__ = [
    # Base exceptions
    "BaseAppException",
    # Authentication & Authorization
    "AuthenticationException",
    "InvalidCredentialsException",
    "TokenExpiredException",
    "TokenInvalidException",
    "AccountLockedException",
    "AuthorizationException",
    "InsufficientPermissionsException",
    "TenantAccessDeniedException",
    # Tenant Management
    "TenantException",
    "TenantSuspendedException",
    "TenantLimitExceededException",
    "TenantNotFoundException",
    # Store Management
    "StoreException",
    "StoreNotFoundException",
    "StoreClosedException",
    "InvalidStoreHoursException",
    # Employee Management
    "EmployeeException",
    "EmployeeNotFoundException",
    "EmployeeNotScheduledException",
    "DuplicateEmployeeException",
    "InvalidShiftException",
    # Product & Inventory
    "ProductException",
    "ProductNotFoundException",
    "DuplicateProductException",
    "InvalidSKUException",
    "InvalidBarcodeException",
    "InventoryException",
    "InsufficientInventoryException",
    "InvalidInventoryAdjustmentException",
    # POS & Transactions
    "TransactionException",
    "InvalidTransactionException",
    "PaymentFailedException",
    "TransactionNotFoundException",
    "RefundException",
    # Customer Management
    "CustomerException",
    "CustomerNotFoundException",
    "DuplicateCustomerException",
    "CustomerBlockedException",
    # Warehouse
    "WarehouseException",
    "WarehouseNotFoundException",
    "InvalidWarehouseLocationException",
    # Validation
    "ValidationException",
    "RequiredFieldException",
    "InvalidEmailException",
    "InvalidPhoneException",
    # File Operations
    "FileException",
    "FileTooLargeException",
    "InvalidFileTypeException",
    # Rate Limiting
    "RateLimitExceededException",
    # Database
    "DatabaseException",
    "RecordNotFoundException",
    "DuplicateRecordException",
    "DatabaseConnectionException",
]
